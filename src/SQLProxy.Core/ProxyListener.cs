using System.Net;
using System.Net.Sockets;

namespace SQLProxy;

/// <summary>
/// One TCP accept-loop for one <see cref="ProxyDefinition"/>. Backend-agnostic — the actual
/// per-connection behavior (Sybase translation vs MSSQL passthrough) is injected as
/// <paramref name="createSession"/>, chosen by <see cref="Worker"/> based on
/// <see cref="ProxyDefinition.BackendType"/>.
/// </summary>
public sealed class ProxyListener(
    ProxyDefinition definition,
    Func<TcpClient, CancellationToken, Task> createSession,
    ILogger<ProxyListener> logger)
{
    public async Task RunAsync(CancellationToken stoppingToken)
    {
        var listener = new TcpListener(IPAddress.Any, definition.ListenPort);
        listener.Start();
        logger.LogInformation(
            "Proxy '{Name}' ({BackendType}) escuchando en el puerto {Port}.",
            definition.Name, definition.BackendType, definition.ListenPort);

        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await listener.AcceptTcpClientAsync(stoppingToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }

                _ = HandleClientAsync(client, stoppingToken);
            }
        }
        finally
        {
            listener.Stop();
            logger.LogInformation("Proxy '{Name}': dejó de escuchar en el puerto {Port}.", definition.Name, definition.ListenPort);
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken stoppingToken)
    {
        try
        {
            await createSession(client, stoppingToken);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Proxy '{Name}': sesión de cliente terminó con un error no capturado.", definition.Name);
        }
    }
}
