namespace SQLProxy.Desktop;

/// <summary>Flattened, display-ready view of one <see cref="ManagedProxy"/> for the DataGrid — no
/// INotifyPropertyChanged, the grid's bound collection is simply rebuilt on every ProxyManager
/// "Changed" event instead of patching individual rows in place (small list, not worth the extra
/// plumbing).</summary>
public sealed class ProxyRow
{
    public required string Name { get; init; }
    public required int ListenPort { get; init; }
    public required ProxyBackendType BackendType { get; init; }
    public required string Target { get; init; }
    public required bool IsRunning { get; init; }
    public required bool AutoStart { get; init; }
    public string? LastError { get; init; }

    public string Status => LastError is not null ? $"Error: {LastError}" : IsRunning ? "Corriendo" : "Detenido";

    public static ProxyRow From(ManagedProxy proxy)
    {
        var d = proxy.Definition;
        var target = d.BackendType switch
        {
            ProxyBackendType.Sybase => $"{d.Sybase?.Server}:{d.Sybase?.Port}",
            ProxyBackendType.MssqlPassthrough => $"{d.MssqlPassthrough?.Server}:{d.MssqlPassthrough?.Port}",
            _ => "",
        };
        return new ProxyRow
        {
            Name = d.Name,
            ListenPort = d.ListenPort,
            BackendType = d.BackendType,
            Target = target,
            IsRunning = proxy.IsRunning,
            AutoStart = d.AutoStart,
            LastError = proxy.LastError,
        };
    }
}
