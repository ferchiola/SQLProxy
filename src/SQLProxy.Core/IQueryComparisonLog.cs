namespace SQLProxy;

/// <summary>
/// The "meeting point" between the Sybase and MSSQL-passthrough proxies: both write one record per
/// handled query here, so the same SQL text can later be grepped/diffed across both backends
/// instead of capturing Extended Events by hand against a real SQL Server every time.
/// </summary>
public interface IQueryComparisonLog
{
    void Record(string proxyName, string sql, int responseByteLength, TimeSpan elapsed);
}
