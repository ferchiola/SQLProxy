namespace SQLProxy.Tds;

/// <summary>MS-TDS 2.2.6.7 SQL Batch — optional ALL_HEADERS block followed by UCS-2LE SQL text.</summary>
internal static class SqlBatch
{
    public static string ParseSqlText(byte[] body)
    {
        var offset = HeaderLength(body);
        return System.Text.Encoding.Unicode.GetString(body, offset, body.Length - offset);
    }

    // RPC_REQUEST (2.2.6.5) starts with the exact same ALL_HEADERS shape as SqlBatch, so this is
    // also how MssqlPassthroughSession finds where an RPC payload's headers end when it needs to
    // carry them over into a synthesized SqlBatch (see BuildPayload below).
    public static int HeaderLength(byte[] body)
    {
        if (body.Length < 4) return 0;
        var totalLength = BitConverter.ToUInt32(body, 0);
        return totalLength >= 4 && totalLength <= body.Length ? (int)totalLength : 0;
    }

    // Rebuilds a SqlBatch payload with the same ALL_HEADERS prefix as `originalBody` (so an active
    // transaction descriptor, if any, carries over unchanged) but different SQL text — used by
    // MssqlPassthroughSession (2026-10-27) to push masking down into the query text itself before
    // forwarding to the real backend, instead of decoding/re-encoding every row on the way back.
    public static byte[] BuildPayload(byte[] originalBody, string newSqlText)
    {
        var headerLength = HeaderLength(originalBody);
        var textBytes = System.Text.Encoding.Unicode.GetBytes(newSqlText);
        var result = new byte[headerLength + textBytes.Length];
        Array.Copy(originalBody, 0, result, 0, headerLength);
        Array.Copy(textBytes, 0, result, headerLength, textBytes.Length);
        return result;
    }
}
