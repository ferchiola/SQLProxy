using System.Windows;
using System.Windows.Controls;

namespace SQLProxy.Desktop;

public partial class ProxyEditWindow : Window
{
    /// <summary>Set after a successful OK click — null until then.</summary>
    public ProxyDefinition? Result { get; private set; }

    /// <summary>Pass an existing definition to edit it, or null to create a new one.</summary>
    public ProxyEditWindow(ProxyDefinition? existing)
    {
        InitializeComponent();
        MaskTypeCombo.SelectedIndex = 0;

        if (existing is null)
        {
            BackendCombo.SelectedIndex = 0;
            return;
        }

        Title = $"Editar proxy '{existing.Name}'";
        NameBox.Text = existing.Name;
        ListenPortBox.Text = existing.ListenPort.ToString();
        AutoStartCheck.IsChecked = existing.AutoStart;
        BackendCombo.SelectedIndex = existing.BackendType == ProxyBackendType.Sybase ? 0 : 1;

        if (existing.Sybase is { } sybase)
        {
            SybaseServerBox.Text = sybase.Server;
            SybasePortBox.Text = sybase.Port.ToString();
        }
        if (existing.MssqlPassthrough is { } mssql)
        {
            MssqlServerBox.Text = mssql.Server;
            MssqlPortBox.Text = mssql.Port.ToString();
        }
        foreach (var field in existing.MaskedFields)
            MaskedFieldsList.Items.Add(field.Clone());
    }

    private void MaskTypeCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        // ReplacementTextLabel/Box might not exist yet during InitializeComponent's own
        // SelectionChanged firing for the initial SelectedIndex assignment.
        if (ReplacementTextBox is null) return;
        var isSha256 = MaskTypeCombo.SelectedIndex == 1;
        ReplacementTextLabel.Visibility = isSha256 ? Visibility.Collapsed : Visibility.Visible;
        ReplacementTextBox.Visibility = isSha256 ? Visibility.Collapsed : Visibility.Visible;
    }

    private void MaskedFieldsList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (MaskedFieldsList.SelectedItem is not MaskedField mask) return;
        MaskedFieldInputBox.Text = mask.Field;
        MaskTypeCombo.SelectedIndex = mask.Type == MaskType.Sha256 ? 1 : 0;
        ReplacementTextBox.Text = mask.ReplacementText;
    }

    private void AddMaskedField_Click(object sender, RoutedEventArgs e)
    {
        var value = MaskedFieldInputBox.Text.Trim();
        if (value.Length == 0) return;
        if (!value.Contains('.'))
        {
            MessageBox.Show(this, "El campo tiene que tener el formato Tabla.Campo.", "Formato inválido", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var type = MaskTypeCombo.SelectedIndex == 1 ? MaskType.Sha256 : MaskType.Placeholder;
        var replacement = ReplacementTextBox.Text;

        // Updating an existing entry (same Field, case-insensitive) replaces it in place instead of
        // duplicating — lets the user re-select a row, tweak it, and hit the same button to edit.
        var existingIndex = -1;
        for (var i = 0; i < MaskedFieldsList.Items.Count; i++)
            if (((MaskedField)MaskedFieldsList.Items[i]!).Field.Equals(value, StringComparison.OrdinalIgnoreCase))
                { existingIndex = i; break; }

        var updated = new MaskedField { Field = value, Type = type, ReplacementText = replacement };
        if (existingIndex >= 0)
            MaskedFieldsList.Items[existingIndex] = updated;
        else
            MaskedFieldsList.Items.Add(updated);

        MaskedFieldInputBox.Clear();
        MaskTypeCombo.SelectedIndex = 0;
        ReplacementTextBox.Text = "(Valor no disponible)";
    }

    private void RemoveMaskedField_Click(object sender, RoutedEventArgs e)
    {
        if (MaskedFieldsList.SelectedItem is MaskedField selected)
            MaskedFieldsList.Items.Remove(selected);
    }

    private void BackendCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        var isSybase = BackendCombo.SelectedIndex == 0;
        SybasePanel.Visibility = isSybase ? Visibility.Visible : Visibility.Collapsed;
        MssqlPanel.Visibility = isSybase ? Visibility.Collapsed : Visibility.Visible;
    }

    private void OkButton_Click(object sender, RoutedEventArgs e)
    {
        var name = NameBox.Text.Trim();
        if (name.Length == 0)
        {
            MessageBox.Show(this, "El nombre es obligatorio.", "Dato faltante", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        if (!int.TryParse(ListenPortBox.Text.Trim(), out var listenPort) || listenPort is <= 0 or > 65535)
        {
            MessageBox.Show(this, "El puerto de escucha tiene que ser un número entre 1 y 65535.", "Dato inválido", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var isSybase = BackendCombo.SelectedIndex == 0;
        AseBackendOptions? sybaseOptions = null;
        MssqlBackendOptions? mssqlOptions = null;

        if (isSybase)
        {
            if (!int.TryParse(SybasePortBox.Text.Trim(), out var asePort))
            {
                MessageBox.Show(this, "El puerto de ASE tiene que ser un número.", "Dato inválido", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            sybaseOptions = new AseBackendOptions { Server = SybaseServerBox.Text.Trim(), Port = asePort };
        }
        else
        {
            if (!int.TryParse(MssqlPortBox.Text.Trim(), out var mssqlPort))
            {
                MessageBox.Show(this, "El puerto de SQL Server tiene que ser un número.", "Dato inválido", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            mssqlOptions = new MssqlBackendOptions { Server = MssqlServerBox.Text.Trim(), Port = mssqlPort };
        }

        Result = new ProxyDefinition
        {
            Name = name,
            ListenPort = listenPort,
            BackendType = isSybase ? ProxyBackendType.Sybase : ProxyBackendType.MssqlPassthrough,
            AutoStart = AutoStartCheck.IsChecked == true,
            Sybase = sybaseOptions,
            MssqlPassthrough = mssqlOptions,
            MaskedFields = MaskedFieldsList.Items.Cast<MaskedField>().ToList(),
        };
        DialogResult = true;
    }
}
