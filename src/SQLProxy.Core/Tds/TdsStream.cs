using System.Buffers.Binary;

namespace SQLProxy.Tds;

/// <summary>
/// Reads/writes whole TDS messages over a NetworkStream, reassembling and splitting the
/// 8-byte-header packet framing (MS-TDS 2.2.3). Only the framing is handled here — token/body
/// content is parsed/built elsewhere.
/// </summary>
internal sealed class TdsStream
{
    private const int HeaderSize = 8;

    // Packet size used for OUR outgoing packets. We don't honour the client's negotiated
    // PacketSize from LOGIN7 yet (MVP) — 4096 is the TDS default and is accepted by every client.
    private const int OutgoingPacketSize = 4096;

    private readonly Stream _stream;
    private byte _nextPacketId = 1;

    public TdsStream(Stream stream) => _stream = stream;

    public async Task<(byte Type, byte[] Payload)> ReadMessageAsync(CancellationToken ct)
    {
        using var payload = new MemoryStream();
        byte type = 0;
        bool first = true;

        while (true)
        {
            var header = await ReadExactAsync(HeaderSize, ct);
            if (header is null)
            {
                if (first) return (0, Array.Empty<byte>()); // clean disconnect before any data
                throw new IOException("Conexión TDS cortada en medio de un mensaje.");
            }

            if (first)
            {
                type = header[0];
                first = false;
            }

            var status = header[1];
            var length = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(2, 2));
            var chunkLength = length - HeaderSize;
            if (chunkLength < 0)
                throw new IOException($"Longitud de paquete TDS inválida: {length}.");

            if (chunkLength > 0)
            {
                var chunk = await ReadExactAsync(chunkLength, ct)
                    ?? throw new IOException("Conexión TDS cortada en medio de un paquete.");
                payload.Write(chunk, 0, chunk.Length);
            }

            if ((status & TdsStatus.EndOfMessage) != 0)
                break;
        }

        return (type, payload.ToArray());
    }

    public async Task WriteMessageAsync(byte type, byte[] payload, CancellationToken ct)
    {
        var offset = 0;
        var remaining = payload.Length;

        do
        {
            var chunkLen = Math.Min(remaining, OutgoingPacketSize - HeaderSize);
            var isLast = chunkLen == remaining;

            var packet = new byte[HeaderSize + chunkLen];
            packet[0] = type;
            packet[1] = isLast ? TdsStatus.EndOfMessage : TdsStatus.Normal;
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2, 2), (ushort)packet.Length);
            packet[4] = 0; // SPID hi
            packet[5] = 0; // SPID lo
            packet[6] = _nextPacketId++;
            packet[7] = 0; // window

            Buffer.BlockCopy(payload, offset, packet, HeaderSize, chunkLen);
            await _stream.WriteAsync(packet, ct);

            offset += chunkLen;
            remaining -= chunkLen;
        } while (remaining > 0);

        await _stream.FlushAsync(ct);
    }

    private async Task<byte[]?> ReadExactAsync(int count, CancellationToken ct)
    {
        var buffer = new byte[count];
        var read = 0;
        while (read < count)
        {
            var n = await _stream.ReadAsync(buffer.AsMemory(read, count - read), ct);
            if (n == 0)
                return read == 0 ? null : throw new IOException("Conexión TDS cortada a mitad de una lectura.");
            read += n;
        }
        return buffer;
    }
}
