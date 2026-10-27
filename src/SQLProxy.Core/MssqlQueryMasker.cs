using System.Text.RegularExpressions;

namespace SQLProxy;

/// <summary>
/// Pushes masking down into the SQL text itself for the MSSQL-passthrough proxy (2026-10-27),
/// replacing the earlier approach (MssqlTranslatedSession: decode every row via SqlDataReader, mask
/// it, re-encode it by hand through TokenWriter). That approach kept drifting from what a real SQL
/// Server actually sends on the wire — it fabricated its own LOGINACK (wrong version, caught SMO's
/// "Specified cast is not valid" cross-check against the real backend's SERVERPROPERTY), and every
/// column type it didn't map exactly right was another potential client-side crash with no server-
/// side error to grep for. Per the user (2026-10-27): for MSSQL, only the query text that references
/// a masked Table.Field should be touched — everything else (the whole connection handshake, every
/// other query, every other column, WHERE/ORDER BY on the masked column itself) stays a byte-for-
/// byte MssqlPassthroughSession relay, so the real SQL Server encodes its own (already-masked)
/// response in its own always-correct native format. There's nothing left for this proxy kind to
/// get wrong about TDS wire types or version numbers, because it no longer fabricates either.
/// </summary>
internal static class MssqlQueryMasker
{
    // Mirrors MaskedFieldResolver's own FROM-table regex — "which FROM bounds the SELECT list" has
    // to agree with "which table decided these columns need masking" in the first place, since both
    // come from the same text.
    private static readonly Regex FromKeywordRegex = new(@"\bFROM\s+(?:\[?\w+\]?\.)*\[?\w+\]?", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>Returns the original text unchanged if no configured masked field applies to this
    /// query's table. Otherwise returns a rewritten query where each masked column's SELECT-list
    /// expression is replaced with a CASE that computes the masked value server-side — the real
    /// column keeps being used (and stays real) everywhere else in the query.</summary>
    public static string Apply(string sql, IReadOnlyList<MaskedField> maskedFields)
    {
        var columns = MaskedFieldResolver.Resolve(sql, maskedFields);
        if (columns.Count == 0) return sql;

        var fromMatch = FromKeywordRegex.Match(sql);
        if (!fromMatch.Success) return sql; // Resolve() above already required this same match to succeed

        var selectPart = sql[..fromMatch.Index];
        var rest = sql[fromMatch.Index..];

        foreach (var (columnName, mask) in columns)
            selectPart = RewriteColumn(selectPart, columnName, mask);

        return selectPart + rest;
    }

    // Known limitation, same spirit as MaskedFieldResolver's own "only the first FROM table": if the
    // column is never spelled out in the SELECT list as its own name (e.g. "SELECT *"), there's
    // nothing textual to rewrite and the query passes through unmasked — logged at Debug by the
    // caller so it isn't a silent gap.
    private static string RewriteColumn(string selectPart, string columnName, MaskedField mask)
    {
        var escaped = Regex.Escape(columnName);
        var pattern = $@"(?<target>(?:(?:\[[^\]]+\]|\w+)\s*\.\s*)*(?:\[{escaped}\]|\b{escaped}\b))(?<alias>\s*\bAS\b\s*(?:\[[^\]]+\]|\w+))?";
        var regex = new Regex(pattern, RegexOptions.IgnoreCase);

        // Only the first occurrence — a column is projected once in a normal SELECT list; a second
        // match further in the same text segment is far more likely a coincidental identifier than
        // a second projection of the same column.
        return regex.Replace(selectPart, m =>
        {
            var target = m.Groups["target"].Value;
            var alias = m.Groups["alias"].Success ? StripAsKeyword(m.Groups["alias"].Value) : $"[{columnName}]";
            return $"{BuildMaskExpression(target, mask)} AS {alias}";
        }, 1);
    }

    private static string StripAsKeyword(string aliasClause)
    {
        var trimmed = aliasClause.TrimStart();
        return trimmed[2..].Trim(); // "AS X" -> "X" ("AS" is always exactly 2 chars)
    }

    // NULL stays NULL regardless of mask type — same semantics as AseResultMapper/SqlResultMapper's
    // own MaskValue, just computed by the backend's own CASE instead of by this proxy after the
    // fact. HASHBYTES already returns NULL for a NULL input on its own, but spelling it out with an
    // explicit CASE keeps both branches symmetric and obviously correct without relying on that.
    private static string BuildMaskExpression(string target, MaskedField mask) => mask.Type switch
    {
        MaskType.Sha256 =>
            $"CASE WHEN {target} IS NULL THEN NULL ELSE CONVERT(varchar(64), HASHBYTES('SHA2_256', CONVERT(nvarchar(4000), {target})), 2) END",
        _ =>
            $"CASE WHEN {target} IS NULL THEN NULL ELSE N'{mask.ReplacementText.Replace("'", "''")}' END",
    };
}
