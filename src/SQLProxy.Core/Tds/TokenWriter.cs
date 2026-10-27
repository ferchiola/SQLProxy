using System.Buffers.Binary;
using System.Text;

namespace SQLProxy.Tds;

internal static class TokenType
{
    public const byte LoginAck = 0xAD;
    public const byte FeatureExtAck = 0xAE;
    public const byte EnvChange = 0xE3;
    public const byte Error = 0xAA;
    public const byte Info = 0xAB;
    public const byte Done = 0xFD;
    public const byte DoneInProc = 0xFF;
    public const byte ColMetadata = 0x81;
    public const byte Row = 0xD1;
}

internal static class EnvChangeType
{
    public const byte Database = 0x01;
    public const byte Language = 0x02;
    public const byte PacketSize = 0x04;
    public const byte Collation = 0x07;
    public const byte BeginTransaction = 0x08;
    public const byte CommitTransaction = 0x09;
    public const byte RollbackTransaction = 0x0A;
}

// Raw 5-byte COLLATION structure, captured byte-for-byte from a real SQL Server's LOGIN response
// (via the mssql-passthrough proxy — see CLAUDE.md bug #35) for SQL_Latin1_General_CP1_CI_AS,
// which is the same collation this project already claims everywhere else
// (ServerPropertyValues["Collation"] etc.). LCID=1033, sortId=52 — matches.
internal static class CollationBytes
{
    public static readonly byte[] SqlLatin1GeneralCp1CiAs = { 0x09, 0x04, 0xD0, 0x00, 0x34 };
}

[Flags]
internal enum DoneStatus : ushort
{
    Final = 0x00,
    More = 0x01,
    Error = 0x02,
    Count = 0x10,
    Attention = 0x20,
}

/// <summary>
/// The column shapes this MVP proxy understands. Everything that isn't an integer/float/bool is
/// surfaced to the client as NVARCHAR text (via ToString()) — see Notes in the project CLAUDE.md
/// for why, and what a real implementation would need to add (DECIMALN/DATETIMEN/... TYPE_INFO).
/// </summary>
internal enum ProxyColumnKind
{
    Byte, // tinyint — distinct from Int32 because some SMO columns (sys.databases.state, etc.)
          // are declared tinyint in real SQL Server, and a strongly-typed client call like
          // reader.GetByte(ordinal) throws an InvalidCastException against an INTN(4) column —
          // silently, client-side, no new round-trip — which is exactly what made Object Explorer
          // show "(0)" databases with no visible error (see CLAUDE.md bug #22).
    Int32,
    Int64,
    Double,
    Boolean,
    String,
    // DATETIMNTYPE (nullable datetime) — added specifically because a real sys.tables.create_date
    // is `datetime`, and sending it as NVARCHAR (the project's usual fallback for "anything else")
    // caused the exact same silent client-side swallow as CLAUDE.md bug #22 (sys.databases.state
    // being INTN where tinyint was expected) — SMO's Object Explorer "Tables" node showing 0 rows
    // with no error, no retry, nothing in the log, even though the probe matched and returned real
    // data. Encoded as 2 little-endian int32s: days since 1900-01-01, then 1/300-second ticks since
    // midnight — MS-TDS 2.2.5.5.1.5's legacy 8-byte DATETIME wire format.
    DateTime,
}

internal sealed record ProxyColumn(string Name, ProxyColumnKind Kind);

/// <summary>Builds MS-TDS 2.2.7 token stream fragments for the pieces this proxy emits.</summary>
internal sealed class TokenWriter
{
    private readonly MemoryStream _buffer = new();

    public byte[] ToArray() => _buffer.ToArray();

    // Only ever used by SybaseClientSession — ASE has no real SQL Server version to contradict this,
    // so a fixed, modern-looking claim is fine (unlike the MSSQL side, which relays a real SQL
    // Server's own genuine LOGINACK untouched via MssqlPassthroughSession and so never fabricates a
    // version at all).
    public void WriteLoginAck(string serverName)
    {
        using var body = new MemoryStream();
        body.WriteByte(0x01); // Interface: SQL_DFLT
        var tdsVersion = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(tdsVersion, 0x74000004); // TDS 7.4
        body.Write(tdsVersion);
        WriteBVarChar(body, serverName);
        // SSMS/ODBC gate on this: a MajorVer that reads as "older than SQL Server 2000" (< 8) gets
        // rejected outright with "can only connect to SQL Server 2000 or later" before any login
        // happens. Claim a modern-looking version (matches the PRELOGIN version in PreLogin.cs).
        body.WriteByte(15); // MajorVer
        body.WriteByte(0);  // MinorVer
        body.WriteByte(0);  // BuildNumHi
        body.WriteByte(0);  // BuildNumLo

        WriteTokenHeader(TokenType.LoginAck, (int)body.Length);
        body.Position = 0;
        body.CopyTo(_buffer);
    }

    // MS-TDS 2.2.7.10 FEATUREEXTACK — acknowledges (or explicitly declines) the feature-extension
    // requests a TDS 7.4+ LOGIN7 carries (session recovery, column encryption, federated auth,
    // UTF8 support, ...). We never parsed/implemented any of those features and never sent this
    // token at all — a real server always sends it (even if just to say "none of these"), via a
    // single terminator byte when it has nothing to acknowledge. Omitting it entirely leaves
    // whatever the client requested unacknowledged rather than explicitly declined, which is a
    // real gap worth closing even though it didn't resolve the TdsExecuteRPC null-deref crash this
    // was added to test (see CLAUDE.md — the crash turned out to be unrelated to MARS/version too).
    public void WriteEmptyFeatureExtAck()
    {
        _buffer.WriteByte(TokenType.FeatureExtAck);
        _buffer.WriteByte(0xFF); // terminator — no features acknowledged
    }

    public void WriteEnvChangeDatabase(string newValue, string oldValue) =>
        WriteEnvChangeBVarChar(EnvChangeType.Database, newValue, oldValue);

    // Real SQL Server sends these three alongside Database right in the LOGIN response itself
    // (before the LOGINACK token, in fact — verified byte-for-byte against a real SQL Server via
    // the mssql-passthrough proxy's comparison log, see CLAUDE.md bug #35). We only ever sent
    // EnvChange(Database) — Language/Collation/PacketSize were missing entirely on every single
    // connection, from the very first message. Prime suspect for the deferred, client-side-only
    // TdsExecuteRPC crash: these are exactly the kind of connection-level state
    // (Microsoft.Data.SqlClient's SqlCollation/ driver-side language tracking) that could leave
    // something null/uninitialized client-side until a much later, unrelated-looking operation
    // touches it.
    public void WriteEnvChangeLanguage(string newValue, string oldValue) =>
        WriteEnvChangeBVarChar(EnvChangeType.Language, newValue, oldValue);

    public void WriteEnvChangePacketSize(string newValue, string oldValue) =>
        WriteEnvChangeBVarChar(EnvChangeType.PacketSize, newValue, oldValue);

    private void WriteEnvChangeBVarChar(byte type, string newValue, string oldValue)
    {
        using var body = new MemoryStream();
        body.WriteByte(type);
        WriteBVarCharUnicode(body, newValue);
        WriteBVarCharUnicode(body, oldValue);

        WriteTokenHeader(TokenType.EnvChange, (int)body.Length);
        body.Position = 0;
        body.CopyTo(_buffer);
    }

    // COLLATION is a fixed 5-byte structure (LCID+flags+version packed into 4 bytes, +1 sortId
    // byte), B_VARBYTE-encoded (1-byte length prefix). newValue/oldValue are that raw 5-byte blob
    // (or empty for "no previous collation", e.g. a fresh connection) — see
    // CollationBytes.SqlLatin1GeneralCp1CiAs below for where the actual bytes come from.
    public void WriteEnvChangeCollation(byte[] newValue, byte[] oldValue) =>
        WriteEnvChangeBVarByte(EnvChangeType.Collation, newValue, oldValue);

    // Transaction descriptor ENVCHANGEs (MS-TDS 2.2.7.9) — same B_VARBYTE-pair shape as COLLATION,
    // just a different type byte per transaction event and an 8-byte transaction descriptor instead
    // of a 5-byte collation blob. newValue is the (now-active) descriptor for Begin, empty for
    // Commit/Rollback; oldValue is the opposite. See SybaseClientSession's Transaction Manager
    // Request handling (CLAUDE.md, 2026-10-27) for why this exists — SSMS's "New Table" designer
    // wraps its CREATE TABLE in a real client-driven transaction via TDS type 0x0E, not a "BEGIN
    // TRAN" text batch, and silently ignoring that left it hanging forever with nothing ever sent.
    public void WriteEnvChangeTransaction(byte envChangeType, byte[] newValue, byte[] oldValue) =>
        WriteEnvChangeBVarByte(envChangeType, newValue, oldValue);

    private void WriteEnvChangeBVarByte(byte type, byte[] newValue, byte[] oldValue)
    {
        using var body = new MemoryStream();
        body.WriteByte(type);
        body.WriteByte((byte)newValue.Length);
        body.Write(newValue);
        body.WriteByte((byte)oldValue.Length);
        body.Write(oldValue);

        WriteTokenHeader(TokenType.EnvChange, (int)body.Length);
        body.Position = 0;
        body.CopyTo(_buffer);
    }

    public void WriteError(int number, string message, string serverName) =>
        WriteMessageToken(TokenType.Error, number, 1, 16, message, serverName);

    // Real SQL Server sends these right after LOGIN (and after any statement that implicitly
    // changes session state, e.g. a USE or the first batch on a connection) — "Changed database
    // context to 'X'." (5701), "Changed language setting to X." (5703). Purely informational, but
    // omitting them is still a divergence from what a real server's LOGIN response looks like.
    public void WriteInfo(int number, string message, string serverName) =>
        WriteMessageToken(TokenType.Info, number, 1, 0, message, serverName);

    private void WriteMessageToken(byte tokenType, int number, byte state, byte classSeverity, string message, string serverName)
    {
        using var body = new MemoryStream();
        WriteInt32(body, number);
        body.WriteByte(state);
        body.WriteByte(classSeverity);
        var msgBytes = Encoding.Unicode.GetBytes(message);
        WriteUInt16(body, (ushort)message.Length);
        body.Write(msgBytes);
        WriteBVarCharUnicode(body, serverName);
        WriteBVarCharUnicode(body, "SQLProxy");
        WriteUInt32(body, 0); // LineNumber (DWORD form, TDS 7.2+)

        var bytes = body.ToArray();
        WriteTokenHeader(tokenType, bytes.Length);
        _buffer.Write(bytes);
    }

    // Real SQL Server distinguishes the completion of each statement inside a multi-statement
    // batch (DONEINPROC, 0xFF) from the completion of the whole request (DONE, 0xFD) — only the
    // very last result set gets a plain DONE. Every multi-result-set probe here (BuildEditionProbeResponse
    // and friends) was sending plain DONE with the "More" flag for every intermediate result too,
    // which is a real protocol deviation from what Microsoft.Data.SqlClient's TdsParser expects.
    // Suspected as the root cause of a corrupted TdsParser/_stateObj surfacing later as a
    // client-side NullReferenceException deep inside TdsExecuteRPC when SMO reuses the same
    // connection for an unrelated command (e.g. the Policy-Based Management health-state check) —
    // see CLAUDE.md bug #32/#33. The "More" flag itself (not just the token byte) is what signals
    // this, so pick the token type from it instead of adding a separate parameter everywhere.
    public void WriteDone(DoneStatus status, ulong rowCount)
    {
        var token = (status & DoneStatus.More) != 0 ? TokenType.DoneInProc : TokenType.Done;
        _buffer.WriteByte(token);
        WriteUInt16(_buffer, (ushort)status);
        WriteUInt16(_buffer, 0); // CurCmd
        WriteUInt64(_buffer, rowCount);
    }

    public void WriteColumnMetadata(IReadOnlyList<ProxyColumn> columns)
    {
        _buffer.WriteByte(TokenType.ColMetadata);
        WriteUInt16(_buffer, (ushort)columns.Count);

        foreach (var col in columns)
        {
            WriteUInt32(_buffer, 0); // UserType
            WriteUInt16(_buffer, 0x0009); // Flags: nullable + case-insensitive, good enough default
            WriteTypeInfo(col.Kind);
            WriteBVarCharUnicode(_buffer, col.Name);
        }
    }

    public void WriteRow(IReadOnlyList<ProxyColumn> columns, object?[] values)
    {
        _buffer.WriteByte(TokenType.Row);
        for (var i = 0; i < columns.Count; i++)
            WriteValue(columns[i].Kind, values[i]);
    }

    private void WriteTypeInfo(ProxyColumnKind kind)
    {
        switch (kind)
        {
            case ProxyColumnKind.Byte:
                _buffer.WriteByte(0x26); // INTNTYPE
                _buffer.WriteByte(1);    // max length — tinyint
                break;
            case ProxyColumnKind.Int32:
                _buffer.WriteByte(0x26); // INTNTYPE
                _buffer.WriteByte(4);    // max length
                break;
            case ProxyColumnKind.Int64:
                _buffer.WriteByte(0x26);
                _buffer.WriteByte(8);
                break;
            case ProxyColumnKind.Double:
                _buffer.WriteByte(0x6D); // FLTNTYPE
                _buffer.WriteByte(8);
                break;
            case ProxyColumnKind.Boolean:
                _buffer.WriteByte(0x68); // BITNTYPE
                _buffer.WriteByte(1);
                break;
            case ProxyColumnKind.String:
                _buffer.WriteByte(0xE7); // NVARCHARTYPE
                WriteUInt16(_buffer, 4000 * 2);
                _buffer.Write(new byte[] { 0x09, 0x04, 0x00, 0x00, 0x00 }); // generic Latin1_General collation
                break;
            case ProxyColumnKind.DateTime:
                _buffer.WriteByte(0x6F); // DATETIMNTYPE
                _buffer.WriteByte(8);    // max length — legacy 8-byte DATETIME, not the 4-byte SMALLDATETIME form
                break;
        }
    }

    private void WriteValue(ProxyColumnKind kind, object? value)
    {
        switch (kind)
        {
            case ProxyColumnKind.Byte:
                if (value is null) { _buffer.WriteByte(0); break; }
                _buffer.WriteByte(1);
                _buffer.WriteByte(Convert.ToByte(value));
                break;
            case ProxyColumnKind.Int32:
                if (value is null) { _buffer.WriteByte(0); break; }
                _buffer.WriteByte(4);
                WriteInt32(_buffer, Convert.ToInt32(value));
                break;
            case ProxyColumnKind.Int64:
                if (value is null) { _buffer.WriteByte(0); break; }
                _buffer.WriteByte(8);
                WriteInt64(_buffer, Convert.ToInt64(value));
                break;
            case ProxyColumnKind.Double:
                if (value is null) { _buffer.WriteByte(0); break; }
                _buffer.WriteByte(8);
                _buffer.Write(BitConverter.GetBytes(Convert.ToDouble(value)));
                break;
            case ProxyColumnKind.Boolean:
                if (value is null) { _buffer.WriteByte(0); break; }
                _buffer.WriteByte(1);
                _buffer.WriteByte(Convert.ToBoolean(value) ? (byte)1 : (byte)0);
                break;
            case ProxyColumnKind.String:
                if (value is null) { WriteUInt16(_buffer, 0xFFFF); break; }
                var text = Convert.ToString(value) ?? "";
                var bytes = Encoding.Unicode.GetBytes(text);
                WriteUInt16(_buffer, (ushort)bytes.Length);
                _buffer.Write(bytes);
                break;
            case ProxyColumnKind.DateTime:
                if (value is null) { _buffer.WriteByte(0); break; }
                _buffer.WriteByte(8);
                var dt = Convert.ToDateTime(value);
                var days = (int)(dt.Date - new DateTime(1900, 1, 1)).TotalDays;
                var ticks300 = (int)Math.Round(dt.TimeOfDay.TotalSeconds * 300.0);
                WriteInt32(_buffer, days);
                WriteInt32(_buffer, ticks300);
                break;
        }
    }

    private void WriteTokenHeader(byte tokenType, int bodyLength)
    {
        _buffer.WriteByte(tokenType);
        WriteUInt16(_buffer, (ushort)bodyLength);
    }

    private static void WriteBVarChar(Stream s, string value)
    {
        var bytes = Encoding.Unicode.GetBytes(value);
        s.WriteByte((byte)value.Length);
        s.Write(bytes);
    }

    private static void WriteBVarCharUnicode(Stream s, string value) => WriteBVarChar(s, value);

    private static void WriteUInt16(Stream s, ushort value)
    {
        var b = new byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(b, value);
        s.Write(b);
    }

    private static void WriteUInt32(Stream s, uint value)
    {
        var b = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(b, value);
        s.Write(b);
    }

    private static void WriteUInt64(Stream s, ulong value)
    {
        var b = new byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(b, value);
        s.Write(b);
    }

    private static void WriteInt32(Stream s, int value)
    {
        var b = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(b, value);
        s.Write(b);
    }

    private static void WriteInt64(Stream s, long value)
    {
        var b = new byte[8];
        BinaryPrimitives.WriteInt64LittleEndian(b, value);
        s.Write(b);
    }
}
