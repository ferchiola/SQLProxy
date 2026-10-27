using System.Net.Sockets;
using Microsoft.Extensions.Options;

namespace SQLProxy;

/// <summary>
/// Orchestrates N concurrent <see cref="ProxyListener"/>s, one per entry in the "Proxies" config
/// array — each with its own port and its own backend (Sybase-translated or MSSQL-passthrough).
/// Used to be a single hardcoded TCP accept-loop for one ASE backend; see CLAUDE.md for why this
/// grew a second proxy kind (comparing responses against a real SQL Server instead of guessing
/// probe shapes by hand).
/// </summary>
public sealed class Worker : BackgroundService
{
    private readonly ILoggerFactory _loggerFactory;
    private readonly ProxiesOptions _proxiesOptions;
    private readonly IQueryComparisonLog _comparisonLog;

    public Worker(ILoggerFactory loggerFactory, IOptions<ProxiesOptions> proxiesOptions, IQueryComparisonLog comparisonLog)
    {
        _loggerFactory = loggerFactory;
        _proxiesOptions = proxiesOptions.Value;
        _comparisonLog = comparisonLog;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var listeners = _proxiesOptions.Proxies.Select(definition =>
        {
            var listener = new ProxyListener(
                definition,
                (client, ct) => CreateSessionAsync(definition, client, ct),
                _loggerFactory.CreateLogger<ProxyListener>());
            return listener.RunAsync(stoppingToken);
        });

        await Task.WhenAll(listeners);
    }

    private Task CreateSessionAsync(ProxyDefinition definition, TcpClient client, CancellationToken ct) =>
        definition.BackendType switch
        {
            ProxyBackendType.Sybase => new SybaseClientSession(
                client,
                definition.Sybase ?? throw new InvalidOperationException(
                    $"Proxy '{definition.Name}': BackendType=Sybase pero falta la sección 'Sybase' en la configuración."),
                definition.Name,
                _comparisonLog,
                _loggerFactory.CreateLogger<SybaseClientSession>(),
                definition.MaskedFields).RunAsync(ct),

            ProxyBackendType.MssqlPassthrough => new MssqlPassthroughSession(
                client,
                definition.MssqlPassthrough ?? throw new InvalidOperationException(
                    $"Proxy '{definition.Name}': BackendType=MssqlPassthrough pero falta la sección 'MssqlPassthrough' en la configuración."),
                definition.Name,
                _comparisonLog,
                _loggerFactory.CreateLogger<MssqlPassthroughSession>(),
                definition.MaskedFields).RunAsync(ct),

            _ => throw new InvalidOperationException($"Proxy '{definition.Name}': BackendType desconocido."),
        };
}
