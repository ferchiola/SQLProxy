using System.Collections.Concurrent;

namespace SQLProxy.Desktop;

/// <summary>
/// Minimal <see cref="ILoggerProvider"/> that forwards every formatted log line to a single
/// delegate instead of a console/file — the desktop app's log panel is the only "sink" that
/// matters here, there's no need for the full console-logging formatter pipeline.
/// </summary>
public sealed class UiLoggerProvider : ILoggerProvider
{
    private readonly Action<string> _onLine;
    private readonly ConcurrentDictionary<string, UiLogger> _loggers = new();

    public UiLoggerProvider(Action<string> onLine) => _onLine = onLine;

    public ILogger CreateLogger(string categoryName) =>
        _loggers.GetOrAdd(categoryName, name => new UiLogger(name, _onLine));

    public void Dispose() => _loggers.Clear();

    private sealed class UiLogger(string category, Action<string> onLine) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Debug;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            var shortCategory = category.Contains('.') ? category[(category.LastIndexOf('.') + 1)..] : category;
            var message = formatter(state, exception);
            if (exception is not null)
                message += " | " + exception.Message;
            onLine($"{DateTime.Now:HH:mm:ss} [{logLevel}] {shortCategory}: {message}");
        }
    }
}
