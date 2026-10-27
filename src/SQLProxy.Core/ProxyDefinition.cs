namespace SQLProxy;

public enum ProxyBackendType
{
    Sybase,
    MssqlPassthrough,
}

/// <summary>One entry in the "Proxies" config array — one TCP listener, one backend.</summary>
public sealed class ProxyDefinition
{
    public string Name { get; set; } = "";
    public int ListenPort { get; set; }
    public ProxyBackendType BackendType { get; set; }
    public AseBackendOptions? Sybase { get; set; }
    public MssqlBackendOptions? MssqlPassthrough { get; set; }

    // Whether ProxyManager starts this one automatically when the desktop app loads the saved
    // config — a per-proxy on/off switch for "levantar todos al iniciar la aplicación", independent
    // of the user also being able to start/stop it manually at any time regardless of this flag.
    public bool AutoStart { get; set; } = true;

    // "Tabla.Campo" masking rules (2026-10-27) — any query touching one of these (by its primary
    // FROM table + column name, case-insensitive) gets that value replaced — with a fixed
    // configured string, or a SHA-256 hash of the real value — instead of the real data. Applied
    // differently per backend: SybaseClientSession decodes/rebuilds every ASE row by hand and masks
    // the value after the fact; MssqlPassthroughSession instead rewrites the outgoing query text
    // itself (see MssqlQueryMasker) so the real SQL Server computes and encodes the masked value on
    // its own — the MSSQL side never decodes a single result row, masked or not.
    public List<MaskedField> MaskedFields { get; set; } = new();

    public ProxyDefinition Clone() => new()
    {
        Name = Name,
        ListenPort = ListenPort,
        BackendType = BackendType,
        AutoStart = AutoStart,
        MaskedFields = MaskedFields.Select(f => f.Clone()).ToList(),
        Sybase = Sybase is null ? null : new AseBackendOptions
        {
            Server = Sybase.Server, Port = Sybase.Port,
        },
        MssqlPassthrough = MssqlPassthrough is null ? null : new MssqlBackendOptions
        {
            Server = MssqlPassthrough.Server, Port = MssqlPassthrough.Port,
        },
    };
}
