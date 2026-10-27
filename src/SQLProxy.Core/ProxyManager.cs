using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SQLProxy;

/// <summary>Runtime state for one configured proxy — the definition plus whatever's needed to stop it.</summary>
public sealed class ManagedProxy
{
    public ProxyDefinition Definition { get; internal set; }
    public bool IsRunning { get; internal set; }
    public string? LastError { get; internal set; }

    internal CancellationTokenSource? Cts;
    internal Task? RunTask;

    internal ManagedProxy(ProxyDefinition definition) => Definition = definition;
}

/// <summary>
/// Owns the full set of configured proxies for the desktop app: persists them to a JSON file (one
/// save per mutation, not batched — this is a config file a human edits indirectly through the UI,
/// not a high-frequency write path) and starts/stops the underlying <see cref="ProxyListener"/> for
/// each one independently, so turning one proxy on/off never disturbs the others. Replaces the
/// Generic Host's "start every listener once at process startup, run forever" model (still used by
/// the Windows Service host in Worker.cs) with one the desktop UI can drive interactively.
/// </summary>
public sealed class ProxyManager
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    private readonly string _configPath;
    private readonly ILoggerFactory _loggerFactory;
    private readonly IQueryComparisonLog _comparisonLog;
    private readonly List<ManagedProxy> _proxies = new();
    private readonly object _lock = new();

    /// <summary>Raised after any change to the proxy list or any proxy's running state — the UI
    /// re-reads <see cref="Proxies"/> and refreshes from it rather than this event carrying a payload.</summary>
    public event Action? Changed;

    public ProxyManager(string configPath, ILoggerFactory loggerFactory, IQueryComparisonLog comparisonLog)
    {
        _configPath = configPath;
        _loggerFactory = loggerFactory;
        _comparisonLog = comparisonLog;
    }

    public IReadOnlyList<ManagedProxy> Proxies
    {
        get { lock (_lock) return _proxies.ToList(); }
    }

    /// <summary>Loads the saved config (creating an empty one if this is the first run) and starts
    /// every entry with <see cref="ProxyDefinition.AutoStart"/> set.</summary>
    public async Task LoadAndAutoStartAsync()
    {
        List<ProxyDefinition> saved;
        if (File.Exists(_configPath))
        {
            var json = await File.ReadAllTextAsync(_configPath);
            saved = string.IsNullOrWhiteSpace(json)
                ? new List<ProxyDefinition>()
                : JsonSerializer.Deserialize<List<ProxyDefinition>>(json, JsonOptions) ?? new List<ProxyDefinition>();
        }
        else
        {
            saved = new List<ProxyDefinition>();
        }

        lock (_lock)
        {
            _proxies.Clear();
            _proxies.AddRange(saved.Select(d => new ManagedProxy(d)));
        }

        foreach (var proxy in saved.Where(d => d.AutoStart))
            await StartAsync(proxy.Name);

        Changed?.Invoke();
    }

    public async Task AddAsync(ProxyDefinition definition)
    {
        lock (_lock)
        {
            if (_proxies.Any(p => p.Definition.Name.Equals(definition.Name, StringComparison.OrdinalIgnoreCase)))
                throw new InvalidOperationException($"Ya existe un proxy llamado '{definition.Name}'.");
            _proxies.Add(new ManagedProxy(definition));
        }
        Persist();
        Changed?.Invoke();

        if (definition.AutoStart)
            await StartAsync(definition.Name);
    }

    /// <summary>Replaces an existing proxy's definition (possibly renaming it). If it was running,
    /// stops the old listener and starts a new one with the updated settings — a changed port or
    /// backend needs a fresh <see cref="ProxyListener"/>, there's no in-place reconfiguration.</summary>
    public async Task UpdateAsync(string existingName, ProxyDefinition updated)
    {
        ManagedProxy proxy;
        bool wasRunning;
        lock (_lock)
        {
            proxy = _proxies.FirstOrDefault(p => p.Definition.Name.Equals(existingName, StringComparison.OrdinalIgnoreCase))
                ?? throw new InvalidOperationException($"No existe un proxy llamado '{existingName}'.");
            if (!updated.Name.Equals(existingName, StringComparison.OrdinalIgnoreCase)
                && _proxies.Any(p => p.Definition.Name.Equals(updated.Name, StringComparison.OrdinalIgnoreCase)))
                throw new InvalidOperationException($"Ya existe un proxy llamado '{updated.Name}'.");
            wasRunning = proxy.IsRunning;
        }

        if (wasRunning)
            await StopAsync(existingName);

        lock (_lock)
            proxy.Definition = updated;
        Persist();
        Changed?.Invoke();

        if (wasRunning || updated.AutoStart)
            await StartAsync(updated.Name);
    }

    public async Task RemoveAsync(string name)
    {
        await StopAsync(name);
        lock (_lock)
            _proxies.RemoveAll(p => p.Definition.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
        Persist();
        Changed?.Invoke();
    }

    public Task StartAsync(string name)
    {
        ManagedProxy proxy;
        lock (_lock)
        {
            proxy = _proxies.FirstOrDefault(p => p.Definition.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
                ?? throw new InvalidOperationException($"No existe un proxy llamado '{name}'.");
            if (proxy.IsRunning) return Task.CompletedTask;

            proxy.Cts = new CancellationTokenSource();
            proxy.LastError = null;
        }

        var definition = proxy.Definition;
        var cts = proxy.Cts;
        var listener = new ProxyListener(
            definition,
            (client, ct) => CreateSessionAsync(definition, client, ct),
            _loggerFactory.CreateLogger<ProxyListener>());

        proxy.RunTask = Task.Run(async () =>
        {
            try
            {
                await listener.RunAsync(cts!.Token);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                lock (_lock) proxy.LastError = ex.Message;
            }
            finally
            {
                lock (_lock) { proxy.IsRunning = false; proxy.Cts = null; }
                Changed?.Invoke();
            }
        });

        lock (_lock) proxy.IsRunning = true;
        Changed?.Invoke();
        return Task.CompletedTask;
    }

    public async Task StopAsync(string name)
    {
        ManagedProxy? proxy;
        lock (_lock)
            proxy = _proxies.FirstOrDefault(p => p.Definition.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
        if (proxy?.Cts is null) return;

        await proxy.Cts.CancelAsync();
        if (proxy.RunTask is not null)
        {
            try { await proxy.RunTask; } catch { /* already surfaced via LastError */ }
        }

        lock (_lock) { proxy.IsRunning = false; proxy.Cts = null; }
        Changed?.Invoke();
    }

    public async Task StopAllAsync()
    {
        var names = Proxies.Select(p => p.Definition.Name).ToList();
        foreach (var name in names)
            await StopAsync(name);
    }

    private Task CreateSessionAsync(ProxyDefinition definition, TcpClient client, CancellationToken ct) =>
        definition.BackendType switch
        {
            ProxyBackendType.Sybase => new SybaseClientSession(
                client,
                definition.Sybase ?? throw new InvalidOperationException(
                    $"Proxy '{definition.Name}': BackendType=Sybase pero falta la configuración 'Sybase'."),
                definition.Name,
                _comparisonLog,
                _loggerFactory.CreateLogger<SybaseClientSession>(),
                definition.MaskedFields).RunAsync(ct),

            ProxyBackendType.MssqlPassthrough => new MssqlPassthroughSession(
                client,
                definition.MssqlPassthrough ?? throw new InvalidOperationException(
                    $"Proxy '{definition.Name}': BackendType=MssqlPassthrough pero falta la configuración 'MssqlPassthrough'."),
                definition.Name,
                _comparisonLog,
                _loggerFactory.CreateLogger<MssqlPassthroughSession>(),
                definition.MaskedFields).RunAsync(ct),

            _ => throw new InvalidOperationException($"Proxy '{definition.Name}': BackendType desconocido."),
        };

    private void Persist()
    {
        var directory = Path.GetDirectoryName(_configPath);
        if (!string.IsNullOrEmpty(directory))
            Directory.CreateDirectory(directory);

        var definitions = Proxies.Select(p => p.Definition).ToList();
        File.WriteAllText(_configPath, JsonSerializer.Serialize(definitions, JsonOptions));
    }
}
