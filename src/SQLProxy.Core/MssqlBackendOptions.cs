namespace SQLProxy;

/// <summary>
/// Backend target for a "mssql-passthrough" proxy. Deliberately has no credentials: this kind of
/// proxy never authenticates on its own — it forwards whatever LOGIN7 the real client sends,
/// unmodified, straight to this server.
/// </summary>
public sealed class MssqlBackendOptions
{
    public string Server { get; set; } = "";
    public int Port { get; set; } = 1433;
}
