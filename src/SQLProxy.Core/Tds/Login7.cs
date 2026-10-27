namespace SQLProxy.Tds;

/// <summary>
/// MS-TDS 2.2.6.4 LOGIN7. SybaseClientSession forwards whatever user/password the client sent here
/// straight through to ASE instead of using a fixed account — there's no equivalent need on the
/// MSSQL side, since MssqlPassthroughSession relays the client's own raw LOGIN7 bytes to the real
/// SQL Server untouched and never has to parse credentials out of it at all. We also pull out the
/// database the client asked for, as a convenience; everything else (host name/app name/etc.) is
/// parsed just enough to skip over it.
/// </summary>
internal static class Login7
{
    // Offset (from the start of the LOGIN7 body) of the ibDatabase/cchDatabase pair, per MS-TDS
    // 2.2.6.4: 36-byte fixed header, then 9 (ib,cch) UINT16 pairs — HostName, UserName, Password,
    // AppName, ServerName, Extension, CltIntName, Language, Database — 4 bytes each, Database 9th:
    // 36 + 8*4 = 68.
    private const int IbDatabaseOffset = 68;

    public static string? TryGetRequestedDatabase(byte[] body)
    {
        if (body.Length < IbDatabaseOffset + 4) return null;

        var ibDatabase = BitConverter.ToUInt16(body, IbDatabaseOffset);
        var cchDatabase = BitConverter.ToUInt16(body, IbDatabaseOffset + 2);
        if (cchDatabase == 0) return null;

        var byteLen = cchDatabase * 2;
        if (ibDatabase + byteLen > body.Length) return null;

        return System.Text.Encoding.Unicode.GetString(body, ibDatabase, byteLen);
    }

    // UserName is the 2nd (ib,cch) pair (offset 40), Password the 3rd (offset 44) — see the offset
    // table above. Used by SybaseClientSession (2026-10-27): it doesn't authenticate against a fixed
    // ASE account anymore, it needs the client's own real credentials to open its own AseConnection
    // to the backend instead of just relaying bytes. Windows/Integrated auth (blank username, SSPI
    // token instead of a password) isn't handled — TryGetCredentials returns an empty username in
    // that case, which the caller must reject with a clear error rather than silently trying to log
    // in as "".
    private const int IbUserNameOffset = 40;
    private const int IbPasswordOffset = 44;

    public static (string UserName, string Password) TryGetCredentials(byte[] body)
    {
        return (ReadBVarChar(body, IbUserNameOffset), ReadPassword(body, IbPasswordOffset));
    }

    private static string ReadBVarChar(byte[] body, int pairOffset)
    {
        if (body.Length < pairOffset + 4) return "";
        var ib = BitConverter.ToUInt16(body, pairOffset);
        var cch = BitConverter.ToUInt16(body, pairOffset + 2);
        if (cch == 0 || ib + cch * 2 > body.Length) return "";
        return System.Text.Encoding.Unicode.GetString(body, ib, cch * 2);
    }

    // MS-TDS 2.2.6.4: the password is obfuscated (not encrypted) with a fixed per-byte transform —
    // XOR 0xA5, then swap the high/low nibbles. Real SQL Server unscrambles it the same way; this is
    // the exact inverse.
    private static string ReadPassword(byte[] body, int pairOffset)
    {
        if (body.Length < pairOffset + 4) return "";
        var ib = BitConverter.ToUInt16(body, pairOffset);
        var cch = BitConverter.ToUInt16(body, pairOffset + 2);
        if (cch == 0 || ib + cch * 2 > body.Length) return "";

        var raw = new byte[cch * 2];
        Array.Copy(body, ib, raw, 0, raw.Length);
        for (var i = 0; i < raw.Length; i++)
        {
            var b = (byte)(raw[i] ^ 0xA5);
            raw[i] = (byte)(((b << 4) | (b >> 4)) & 0xFF);
        }
        return System.Text.Encoding.Unicode.GetString(raw);
    }
}
