using System.Text.Json;

namespace SQLProxy;

/// <summary>
/// Appends one JSON line per query to a file — simplest possible "meeting point" for comparing
/// what the Sybase proxy and the MSSQL-passthrough proxy each did for the same SQL text. No
/// buffering/batching: dev-only traffic volume, correctness (never lose/interleave a line) matters
/// more than throughput here.
/// </summary>
public sealed class JsonlQueryComparisonLog : IQueryComparisonLog
{
    private readonly string _path;
    private readonly object _lock = new();

    public JsonlQueryComparisonLog(string path) => _path = path;

    public void Record(string proxyName, string sql, int responseByteLength, TimeSpan elapsed)
    {
        var line = JsonSerializer.Serialize(new
        {
            time = DateTimeOffset.Now,
            proxy = proxyName,
            sql,
            responseByteLength,
            elapsedMs = elapsed.TotalMilliseconds,
        });

        lock (_lock)
            File.AppendAllText(_path, line + Environment.NewLine);
    }
}
