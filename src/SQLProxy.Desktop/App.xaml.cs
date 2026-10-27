using System.IO;
using System.Text;
using System.Windows;

namespace SQLProxy.Desktop;

public partial class App : Application
{
    public ProxyManager ProxyManager { get; private set; } = null!;
    public ILoggerFactory LoggerFactory { get; private set; } = null!;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        ShutdownMode = ShutdownMode.OnMainWindowClose;

        // Without this, an unhandled exception on the UI thread (e.g. inside a button click
        // handler) silently kills the window while the process itself lingers with no UI — exactly
        // what happened the first time this shipped (2026-10-27): a background Task.Run that threw
        // during RefreshRows left a windowless zombie process with no visible error at all. Show it
        // instead of guessing from a dead process.
        DispatcherUnhandledException += (_, args) =>
        {
            MessageBox.Show(args.Exception.ToString(), "Error no manejado", MessageBoxButton.OK, MessageBoxImage.Error);
            args.Handled = true;
        };

        // Same reason as the Worker Service host's Program.cs: AdoNetCore.AseClient never
        // registers this itself, and this ASE instance's default charset is a legacy code page.
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

        var appDataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "SQLProxy");
        Directory.CreateDirectory(appDataDir);
        var logFilePath = Path.Combine(appDataDir, "sqlproxy.log");
        var logFileLock = new object();
        // Fresh file per app launch — same convention as the old console host, which always started
        // from an empty proxy.log. Without this the file grows forever across runs and old/new
        // sessions' lines get hard to tell apart.
        File.WriteAllText(logFilePath, "");

        LoggerFactory = Microsoft.Extensions.Logging.LoggerFactory.Create(builder =>
            builder.SetMinimumLevel(LogLevel.Debug).AddProvider(new UiLoggerProvider(line =>
            {
                LogLineReceived?.Invoke(line);
                lock (logFileLock) File.AppendAllText(logFilePath, line + Environment.NewLine);
            })));

        var configPath = Path.Combine(appDataDir, "proxies.json");
        var comparisonLogPath = Path.Combine(appDataDir, "sqlproxy_comparisons.jsonl");

        ProxyManager = new ProxyManager(configPath, LoggerFactory, new JsonlQueryComparisonLog(comparisonLogPath));
    }

    /// <summary>Raised on the background thread that produced the log line — subscribers must
    /// marshal to the UI thread themselves (<c>Dispatcher.Invoke</c>) before touching any control.</summary>
    public event Action<string>? LogLineReceived;

    protected override void OnExit(ExitEventArgs e)
    {
        ProxyManager.StopAllAsync().GetAwaiter().GetResult();
        base.OnExit(e);
    }
}
