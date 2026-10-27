using System.Collections.ObjectModel;
using System.Windows;

namespace SQLProxy.Desktop;

public partial class MainWindow : Window
{
    private readonly App _app;
    private readonly ObservableCollection<ProxyRow> _rows = new();
    private readonly object _logLock = new();
    private int _logLineCount;
    private const int MaxLogLines = 2000;

    public MainWindow()
    {
        InitializeComponent();
        _app = (App)Application.Current;
        ProxyGrid.ItemsSource = _rows;

        _app.ProxyManager.Changed += OnProxiesChanged;
        _app.LogLineReceived += OnLogLine;
        Closed += (_, _) =>
        {
            _app.ProxyManager.Changed -= OnProxiesChanged;
            _app.LogLineReceived -= OnLogLine;
        };

        Loaded += async (_, _) => await _app.ProxyManager.LoadAndAutoStartAsync();
    }

    private void OnProxiesChanged() => Dispatcher.Invoke(RefreshRows);

    private void RefreshRows()
    {
        var selectedName = (ProxyGrid.SelectedItem as ProxyRow)?.Name;
        _rows.Clear();
        foreach (var proxy in _app.ProxyManager.Proxies)
            _rows.Add(ProxyRow.From(proxy));
        if (selectedName is not null)
            ProxyGrid.SelectedItem = _rows.FirstOrDefault(r => r.Name == selectedName);
    }

    private void OnLogLine(string line) => Dispatcher.Invoke(() =>
    {
        lock (_logLock)
        {
            LogBox.AppendText(line + Environment.NewLine);
            if (++_logLineCount > MaxLogLines)
            {
                var text = LogBox.Text;
                var cut = text.IndexOf('\n', text.Length / 4);
                if (cut > 0) LogBox.Text = text[(cut + 1)..];
                _logLineCount = MaxLogLines / 2;
            }
            LogBox.ScrollToEnd();
        }
    });

    private ProxyRow? SelectedRow => ProxyGrid.SelectedItem as ProxyRow;

    private async void AddButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new ProxyEditWindow(null) { Owner = this };
        if (dialog.ShowDialog() != true) return;

        try
        {
            await _app.ProxyManager.AddAsync(dialog.Result!);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "No se pudo agregar el proxy", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async void EditButton_Click(object sender, RoutedEventArgs e)
    {
        var row = RequireSelectedRow();
        if (row is null) return;
        var existing = _app.ProxyManager.Proxies.FirstOrDefault(p => p.Definition.Name == row.Name)?.Definition;
        if (existing is null) return;

        var dialog = new ProxyEditWindow(existing) { Owner = this };
        if (dialog.ShowDialog() != true) return;

        try
        {
            await _app.ProxyManager.UpdateAsync(row.Name, dialog.Result!);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "No se pudo editar el proxy", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async void RemoveButton_Click(object sender, RoutedEventArgs e)
    {
        var row = RequireSelectedRow();
        if (row is null) return;
        var confirm = MessageBox.Show(this, $"¿Eliminar el proxy '{row.Name}'? Si está corriendo, se va a detener.",
            "Confirmar", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes) return;

        await _app.ProxyManager.RemoveAsync(row.Name);
    }

    private async void StartButton_Click(object sender, RoutedEventArgs e)
    {
        var row = RequireSelectedRow();
        if (row is null) return;
        try
        {
            await _app.ProxyManager.StartAsync(row.Name);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "No se pudo iniciar el proxy", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async void StopButton_Click(object sender, RoutedEventArgs e)
    {
        var row = RequireSelectedRow();
        if (row is null) return;
        await _app.ProxyManager.StopAsync(row.Name);
    }

    // Every Edit/Remove/Start/Stop button silently did nothing when no grid row was selected —
    // reported as "el botón Detener no parece funcionar" (2026-10-27) when that was really just a
    // missing selection, with zero feedback either way. This surfaces that case explicitly instead
    // of behaving identically to a real failure.
    private ProxyRow? RequireSelectedRow()
    {
        var row = SelectedRow;
        if (row is null)
            MessageBox.Show(this, "Seleccioná un proxy en la lista primero.", "Nada seleccionado", MessageBoxButton.OK, MessageBoxImage.Information);
        return row;
    }
}
