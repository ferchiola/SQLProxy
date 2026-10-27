namespace SQLProxy;

/// <summary>
/// Backend target for a "Sybase" proxy. Deliberately has no credentials or database (2026-10-27,
/// same shape as <see cref="MssqlBackendOptions"/> now) — like the MSSQL side, this proxy never logs
/// into ASE with a fixed account of its own anymore. <see cref="SybaseClientSession"/> pulls the
/// user/password straight out of the client's own LOGIN7 (the connection string/credentials SSMS
/// was given to call the proxy) and the requested database the same way, then uses those to open
/// the real ASE connection — so whatever account you log into the proxy with in SSMS is the same
/// account that ends up hitting ASE.
/// </summary>
public sealed class AseBackendOptions
{
    public string Server { get; set; } = "";
    public int Port { get; set; } = 5000;

    public string BuildConnectionString(string database, string user, string password) =>
        $"Data Source={Server};Port={Port};Database={database};Uid={user};Pwd={password}";
}
