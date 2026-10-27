using System.Buffers.Binary;

namespace SQLProxy.Tds;

internal static class PreLoginOption
{
    public const byte Version = 0x00;
    public const byte Encryption = 0x01;
    public const byte InstOpt = 0x02;
    public const byte ThreadId = 0x03;
    public const byte Mars = 0x04;
    public const byte Terminator = 0xFF;
}

internal static class EncryptionOption
{
    public const byte NotSupported = 0x02;
}

/// <summary>
/// MS-TDS 2.2.6.4/2.2.6.5 PRELOGIN. We don't support TLS (ENCRYPT_NOT_SUP) — this proxy is meant
/// to run only inside the trusted DEVELOP network, never exposed directly to the internet.
/// </summary>
internal static class PreLogin
{
    private readonly record struct RequestOption(byte Type, int Length);

    public static byte[] BuildResponse(byte[] requestBody)
    {
        var requested = ParseOptions(requestBody);

        // Values we actually want to send for the option types we recognise.
        var values = new Dictionary<byte, byte[]>
        {
            [PreLoginOption.Version] = new byte[] { 15, 0, 0, 0, 0, 0 }, // claim SQL Server 2019 wire compat (0.0.0 reads as "pre-2000" to some drivers)
            [PreLoginOption.Encryption] = new byte[] { EncryptionOption.NotSupported },
            [PreLoginOption.InstOpt] = new byte[] { 0x00 },
            [PreLoginOption.ThreadId] = Array.Empty<byte>(),
            // Tried claiming MARS=1 without implementing real SMUX multiplexing, on the theory
            // that it might route SMO/SqlClient around the "connection busy, no MARS" bookkeeping
            // path that a background-thread TdsExecuteRPC null-deref crash (CLAUDE.md bug #34) was
            // hitting. Disproven by a follow-up procdump capture: the identical crash (same EIP,
            // same null-deref) still happened with MARS=1 — so it isn't about MARS at all. Reverted
            // to the honest answer; lying here was pure unnecessary risk (a client that ever tried
            // genuine SMUX framing against a proxy that doesn't implement it would misbehave).
            [PreLoginOption.Mars] = new byte[] { 0x00 },
        };

        // If the client sent options we don't specifically handle, echo back zeroed bytes of the
        // same length so the offset/length table the client parses stays internally consistent.
        var ordered = requested.Count > 0
            ? requested
            : new List<RequestOption>
            {
                new(PreLoginOption.Version, 6),
                new(PreLoginOption.Encryption, 1),
                new(PreLoginOption.InstOpt, 1),
                new(PreLoginOption.ThreadId, 0),
                new(PreLoginOption.Mars, 1),
            };

        var payloads = new List<byte[]>();
        foreach (var opt in ordered)
            payloads.Add(values.TryGetValue(opt.Type, out var known) ? known : new byte[opt.Length]);

        return Encode(ordered, payloads);
    }

    // Used by MssqlPassthroughSession — the one deliberate exception to "relay everything
    // unmodified". TDS login encryption is negotiated via this PRELOGIN byte and then performed as
    // a raw TLS handshake laid directly on the socket, with NO TDS packet framing around it (MS-TDS
    // 2.2.6.4) — if the real backend's PRELOGIN response says "let's encrypt" (its usual default)
    // and we relay that honestly, the client starts a TLS handshake our message-oriented relay loop
    // has no way to understand, immediately desyncing (observed as "Conexión TDS cortada a mitad de
    // una lectura" after 2-3 retried PRELOGINs). Patching just this one byte — in both directions,
    // client request and server response — keeps the whole connection in plaintext TDS end to end,
    // which this proxy's relay loop can actually parse. Same reasoning the Sybase proxy's own
    // BuildResponse above already uses (ENCRYPT_NOT_SUP unconditionally); this just applies it to
    // bytes we didn't author ourselves.
    public static byte[] ForceEncryptionNotSupported(byte[] body)
    {
        var pos = 0;
        while (pos + 5 <= body.Length && body[pos] != PreLoginOption.Terminator)
        {
            var type = body[pos];
            var offset = BinaryPrimitives.ReadUInt16BigEndian(body.AsSpan(pos + 1, 2));
            var length = BinaryPrimitives.ReadUInt16BigEndian(body.AsSpan(pos + 3, 2));
            if (type == PreLoginOption.Encryption && length == 1 && offset < body.Length)
            {
                var patched = (byte[])body.Clone();
                patched[offset] = EncryptionOption.NotSupported;
                return patched;
            }
            pos += 5;
        }
        return body;
    }

    private static List<RequestOption> ParseOptions(byte[] body)
    {
        var options = new List<RequestOption>();
        var pos = 0;
        while (pos + 5 <= body.Length && body[pos] != PreLoginOption.Terminator)
        {
            var type = body[pos];
            var length = BinaryPrimitives.ReadUInt16BigEndian(body.AsSpan(pos + 3, 2));
            options.Add(new RequestOption(type, length));
            pos += 5;
        }
        return options;
    }

    private static byte[] Encode(List<RequestOption> options, List<byte[]> payloads)
    {
        var tableSize = options.Count * 5 + 1; // + terminator
        var dataSize = payloads.Sum(p => p.Length);
        var result = new byte[tableSize + dataSize];

        var tablePos = 0;
        var dataPos = tableSize;
        for (var i = 0; i < options.Count; i++)
        {
            result[tablePos] = options[i].Type;
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(tablePos + 1, 2), (ushort)dataPos);
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(tablePos + 3, 2), (ushort)payloads[i].Length);
            Buffer.BlockCopy(payloads[i], 0, result, dataPos, payloads[i].Length);
            tablePos += 5;
            dataPos += payloads[i].Length;
        }
        result[tablePos] = PreLoginOption.Terminator;

        return result;
    }
}
