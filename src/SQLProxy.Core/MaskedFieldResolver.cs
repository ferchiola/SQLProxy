using System.Text.RegularExpressions;

namespace SQLProxy;

/// <summary>
/// Shared "which columns does this query need to mask" logic — used by
/// <see cref="SybaseClientSession"/> (masks real ASE row data after the fact) and
/// <see cref="MssqlQueryMasker"/> (rewrites the query text itself before forwarding to a real SQL
/// Server), since the resolution itself (query text in, column-name set out) doesn't depend on
/// which backend engine answers the query or how the masking is actually applied.
/// </summary>
internal static class MaskedFieldResolver
{
    // Resolves the query's PRIMARY table (the first name after FROM, stripping any db/schema
    // qualifiers and brackets — "FROM [Bitcavex].[dbo].[User]", "FROM dbo.User", and "FROM User"
    // all resolve to "User") and returns the masking rule for each column to mask for THAT table.
    // Known limitation: only ever looks at the first table after FROM — a JOIN's second/third table
    // isn't resolved, so a masked field on a joined table won't be caught. Good enough for the
    // common "SELECT ... FROM OneTable" case without parsing a real SQL AST.
    private static readonly Regex FromTableRegex = new(@"\bFROM\s+(?:\[?\w+\]?\.)*\[?(\w+)\]?", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static Dictionary<string, MaskedField> Resolve(string sql, IReadOnlyList<MaskedField> maskedFields)
    {
        var result = new Dictionary<string, MaskedField>(StringComparer.OrdinalIgnoreCase);
        if (maskedFields.Count == 0) return result;

        var match = FromTableRegex.Match(sql);
        if (!match.Success) return result;
        var table = match.Groups[1].Value;

        foreach (var mask in maskedFields)
        {
            var parts = mask.Field.Split('.', 2);
            if (parts.Length == 2 && parts[0].Equals(table, StringComparison.OrdinalIgnoreCase))
                result[parts[1]] = mask;
        }
        return result;
    }
}
