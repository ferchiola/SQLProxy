using System.Security.Cryptography;
using System.Text;
using AdoNetCore.AseClient;
using SQLProxy.Tds;

namespace SQLProxy;

/// <summary>
/// Maps an open AseDataReader's current result set to the small set of TDS column/value kinds
/// TokenWriter knows how to encode. See TokenWriter.ProxyColumnKind for the known limitation that
/// decimal/datetime/binary/etc. all degrade to NVARCHAR text instead of a native TDS type.
/// </summary>
internal static class AseResultMapper
{
    public static List<ProxyColumn> BuildColumns(AseDataReader reader, IReadOnlyDictionary<string, MaskedField>? maskedColumns = null)
    {
        var columns = new List<ProxyColumn>(reader.FieldCount);
        for (var i = 0; i < reader.FieldCount; i++)
        {
            var name = reader.GetName(i);
            // A masked column's OUTPUT is always text (the placeholder string, or a hex SHA-256
            // digest) regardless of the real underlying type — forced to String here so writing
            // that text is actually valid for this column's declared TDS type.
            var kind = maskedColumns is not null && maskedColumns.ContainsKey(name)
                ? ProxyColumnKind.String
                : MapKind(reader.GetFieldType(i));
            columns.Add(new ProxyColumn(name, kind));
        }
        return columns;
    }

    public static object?[] ReadRowValues(AseDataReader reader, int fieldCount, IReadOnlyDictionary<string, MaskedField>? maskedColumns = null)
    {
        var values = new object?[fieldCount];
        for (var i = 0; i < fieldCount; i++)
        {
            if (maskedColumns is not null && maskedColumns.TryGetValue(reader.GetName(i), out var mask))
            {
                values[i] = MaskValue(mask, reader.IsDBNull(i) ? null : reader.GetValue(i));
                continue;
            }
            if (reader.IsDBNull(i)) { values[i] = null; continue; }
            var raw = reader.GetValue(i);
            values[i] = raw is byte[] bytes ? "0x" + Convert.ToHexString(bytes) : raw;
        }
        return values;
    }

    // NULL stays NULL regardless of mask type — there's no real value to hash, and NULL itself
    // isn't the sensitive data (its absence is still informative but that's true of a real server
    // too, and hashing "nothing" into a fixed digest would be actively misleading).
    private static string? MaskValue(MaskedField mask, object? realValue)
    {
        if (realValue is null) return null;
        if (mask.Type != MaskType.Sha256) return mask.ReplacementText;

        var text = realValue is byte[] bytes ? Convert.ToHexString(bytes) : realValue.ToString() ?? "";
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(text));
        return Convert.ToHexString(hash);
    }

    private static ProxyColumnKind MapKind(Type clrType)
    {
        if (clrType == typeof(int) || clrType == typeof(short) || clrType == typeof(byte) || clrType == typeof(sbyte))
            return ProxyColumnKind.Int32;
        if (clrType == typeof(long))
            return ProxyColumnKind.Int64;
        if (clrType == typeof(double) || clrType == typeof(float) || clrType == typeof(decimal))
            return ProxyColumnKind.Double;
        if (clrType == typeof(bool))
            return ProxyColumnKind.Boolean;

        return ProxyColumnKind.String; // DateTime, Guid, string, byte[], AseDecimal, etc.
    }
}
