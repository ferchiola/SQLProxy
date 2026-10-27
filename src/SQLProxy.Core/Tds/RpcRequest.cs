using System.Text;

namespace SQLProxy.Tds;

/// <summary>
/// MS-TDS 2.2.6.5 RPC Request — modern clients (tedious, Microsoft.Data.SqlClient, SSMS) send
/// plain ad-hoc queries as a call to the builtin procedure <c>sp_executesql</c> rather than as a
/// SQLBatch. Originally this only understood the single-parameter shape (just the @stmt text,
/// everything else ignored) — real traffic captured via the mssql-passthrough proxy (see CLAUDE.md
/// bug #36) proved SMO's actual database-property queries use the full
/// <c>sp_executesql @stmt, @params, @param1, ...</c> shape, with a bound parameter
/// (<c>@_msparam_0</c>) substituted into a WHERE clause. Forwarding the template text as-is left
/// the parameter undeclared from ASE's point of view ("Must declare variable '@_msparam_0'").
/// Still not real parameter binding against ASE — just textual substitution of the bound value as
/// a literal into the SQL before handing it to AseCommand, which is good enough for the read-only,
/// simple-typed queries SMO actually sends this way.
/// </summary>
internal static class RpcRequest
{
    private const int SpExecuteSqlProcId = 10;

    private sealed record RpcParam(string Name, object? Value);

    public static string? TryGetExecSqlText(byte[] body)
    {
        var offset = SkipAllHeaders(body);
        if (offset + 2 > body.Length) return null;

        var procNameLenFlag = BitConverter.ToUInt16(body, offset);
        offset += 2;
        if (procNameLenFlag != 0xFFFF) return null; // named (non-builtin) procedure — not supported

        if (offset + 2 > body.Length) return null;
        var procId = BitConverter.ToUInt16(body, offset);
        offset += 2;
        if (procId != SpExecuteSqlProcId) return null;

        offset += 2; // OptionFlags

        var parameters = new List<RpcParam>();
        while (offset < body.Length)
        {
            var param = TryReadParam(body, ref offset);
            if (param is null) break; // unsupported/unparseable type — stop, use whatever we got
            parameters.Add(param);
        }

        if (parameters.Count == 0 || parameters[0].Value is not string stmt) return null;
        if (parameters.Count == 1) return stmt; // plain sp_executesql(@stmt) — nothing to substitute

        // parameters[1] is the @params declaration string, e.g. "@_msparam_0 nvarchar(4000)" or
        // several comma-separated — only the leading "@name" of each matters here, actual
        // declared types are irrelevant since we're substituting literals, not binding.
        if (parameters[1].Value is not string declaration) return stmt;

        var names = declaration
            .Split(',')
            .Select(d => d.TrimStart().Split(' ', 2)[0])
            .ToList();

        var result = stmt;
        for (var i = 0; i < names.Count && i + 2 < parameters.Count; i++)
            result = result.Replace(names[i], ToSqlLiteral(parameters[i + 2].Value), StringComparison.OrdinalIgnoreCase);

        return result;
    }

    private static string ToSqlLiteral(object? value) => value switch
    {
        null => "NULL",
        string s => $"N'{s.Replace("'", "''")}'",
        bool b => b ? "1" : "0",
        _ => Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture) ?? "NULL",
    };

    // One RPC_PARAM: NameLen(1) + Name(UTF16, NameLen*2 bytes) + StatusFlags(1) + TYPE_INFO + Value.
    // Only the few TYPE_INFO shapes SMO's parameterized queries actually use are understood
    // (NVARCHAR, INTN, BITN) — anything else returns null, same "give up gracefully" behavior as
    // before for unsupported RPCs.
    private static RpcParam? TryReadParam(byte[] body, ref int offset)
    {
        if (offset >= body.Length) return null;
        var nameLen = body[offset];
        offset += 1;
        var name = "";
        if (nameLen > 0)
        {
            var nameBytes = nameLen * 2;
            if (offset + nameBytes > body.Length) return null;
            name = Encoding.Unicode.GetString(body, offset, nameBytes);
            offset += nameBytes;
        }

        if (offset >= body.Length) return null;
        offset += 1; // StatusFlags

        if (offset >= body.Length) return null;
        var typeId = body[offset];
        offset += 1;

        object? value;
        switch (typeId)
        {
            case 0xE7: // NVARCHARTYPE
                if (offset + 2 + 5 > body.Length) return null;
                offset += 2 + 5; // MaxLen + Collation
                if (offset + 2 > body.Length) return null;
                var strLen = BitConverter.ToUInt16(body, offset);
                offset += 2;
                if (strLen == 0xFFFF) { value = null; break; }
                if (offset + strLen > body.Length) return null;
                value = Encoding.Unicode.GetString(body, offset, strLen);
                offset += strLen;
                break;

            case 0x26: // INTNTYPE
                if (offset + 1 > body.Length) return null;
                var maxLen = body[offset];
                offset += 1;
                if (offset + 1 > body.Length) return null;
                var intLen = body[offset];
                offset += 1;
                if (intLen == 0) { value = null; break; }
                if (offset + intLen > body.Length) return null;
                value = intLen switch
                {
                    1 => (long)body[offset],
                    2 => BitConverter.ToInt16(body, offset),
                    4 => BitConverter.ToInt32(body, offset),
                    8 => BitConverter.ToInt64(body, offset),
                    _ => (object?)null,
                };
                offset += intLen;
                _ = maxLen;
                break;

            case 0x68: // BITNTYPE
                if (offset + 1 > body.Length) return null;
                offset += 1; // MaxLen (always 1)
                if (offset + 1 > body.Length) return null;
                var bitLen = body[offset];
                offset += 1;
                if (bitLen == 0) { value = null; break; }
                if (offset + 1 > body.Length) return null;
                value = body[offset] != 0;
                offset += 1;
                break;

            default:
                return null; // unsupported type — bail, same as before
        }

        return new RpcParam(name, value);
    }

    /// <summary>
    /// Diagnostic only — describes an RPC call TryGetExecSqlText didn't understand, so it shows up
    /// in the log instead of silently turning into BuildUnsupportedRpcResponse with no trace. In
    /// particular, a NAMED procedure call (ProcNameLenFlag != 0xFFFF — e.g. the ODBC catalog procs
    /// sp_tables/sp_databases/sp_columns, which SSMS/ODBC clients can use instead of a SERVERPROPERTY-
    /// style query to enumerate databases) was a complete blind spot before this: TryGetExecSqlText
    /// returns null for it, and nothing logged which proc was actually being called.
    /// </summary>
    public static string Describe(byte[] body)
    {
        try
        {
            var offset = SkipAllHeaders(body);
            if (offset + 2 > body.Length) return "(no se pudo leer ProcName/ProcId)";

            var procNameLenFlag = BitConverter.ToUInt16(body, offset);
            offset += 2;

            if (procNameLenFlag == 0xFFFF)
            {
                if (offset + 2 > body.Length) return "(no se pudo leer ProcId)";
                var procId = BitConverter.ToUInt16(body, offset);
                return $"procedimiento builtin, id={procId}";
            }

            var byteLen = procNameLenFlag * 2;
            if (offset + byteLen > body.Length) return "(nombre de procedimiento truncado)";
            var name = Encoding.Unicode.GetString(body, offset, byteLen);
            return $"procedimiento con nombre: {name}";
        }
        catch (Exception ex)
        {
            return $"(error describiendo el RPC: {ex.Message})";
        }
    }

    private static int SkipAllHeaders(byte[] body)
    {
        if (body.Length < 4) return 0;
        var totalLength = BitConverter.ToUInt32(body, 0);
        return totalLength >= 4 && totalLength <= body.Length ? (int)totalLength : 0;
    }
}
