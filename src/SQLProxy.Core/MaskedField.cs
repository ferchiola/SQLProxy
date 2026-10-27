using System.Text.Json;
using System.Text.Json.Serialization;

namespace SQLProxy;

public enum MaskType
{
    Placeholder, // replace with a fixed configured string
    Sha256,      // replace with the SHA-256 hash (hex) of the real value
}

/// <summary>One "Tabla.Campo" masking rule for a Sybase-backend proxy (2026-10-27).</summary>
[JsonConverter(typeof(MaskedFieldJsonConverter))]
public sealed class MaskedField
{
    public string Field { get; set; } = ""; // "Tabla.Campo"
    public MaskType Type { get; set; } = MaskType.Placeholder;

    // Only meaningful when Type == Placeholder; ignored for Sha256.
    public string ReplacementText { get; set; } = "(Valor no disponible)";

    public MaskedField Clone() => new() { Field = Field, Type = Type, ReplacementText = ReplacementText };

    public override string ToString() =>
        Type == MaskType.Sha256 ? $"{Field} → SHA-256" : $"{Field} → \"{ReplacementText}\"";
}

/// <summary>
/// Reads both the current object shape AND the old plain-string shape ("TestTabla.email", from
/// before per-field replacement text/SHA-256 existed, 2026-10-27) so proxies.json files saved by
/// the previous version of this feature keep loading instead of throwing and taking down the whole
/// config file. Always WRITES the new object shape — one load silently upgrades old entries.
/// </summary>
public sealed class MaskedFieldJsonConverter : JsonConverter<MaskedField>
{
    public override MaskedField Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.String)
            return new MaskedField { Field = reader.GetString() ?? "" };

        var field = "";
        var type = MaskType.Placeholder;
        var replacement = "(Valor no disponible)";

        using var doc = JsonDocument.ParseValue(ref reader);
        foreach (var prop in doc.RootElement.EnumerateObject())
        {
            switch (prop.Name)
            {
                case "Field": field = prop.Value.GetString() ?? ""; break;
                case "Type": Enum.TryParse(prop.Value.GetString(), ignoreCase: true, out type); break;
                case "ReplacementText": replacement = prop.Value.GetString() ?? replacement; break;
            }
        }
        return new MaskedField { Field = field, Type = type, ReplacementText = replacement };
    }

    public override void Write(Utf8JsonWriter writer, MaskedField value, JsonSerializerOptions options)
    {
        writer.WriteStartObject();
        writer.WriteString("Field", value.Field);
        writer.WriteString("Type", value.Type.ToString());
        writer.WriteString("ReplacementText", value.ReplacementText);
        writer.WriteEndObject();
    }
}
