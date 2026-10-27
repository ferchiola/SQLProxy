using System.Diagnostics;
using System.Net.Sockets;
using SQLProxy.Tds;

namespace SQLProxy;

/// <summary>
/// The MSSQL-passthrough side of the "meeting point": connects to a real SQL Server and relays
/// every TDS message (PRELOGIN, LOGIN7, SqlBatch, RPC, Attention, and whatever the real server
/// answers with) completely unmodified in both directions — this session never fabricates
/// anything, unlike SybaseClientSession. It reuses the same TdsStream message framing already
/// used everywhere else in this project, so payload bytes round-trip byte-for-byte; only packet
/// boundaries can differ, which the protocol doesn't care about.
///
/// The one deliberate exception (2026-10-27): if this proxy has any <see cref="MaskedField"/>s
/// configured, a SqlBatch/RPC whose query touches one of those Table.Field pairs gets its outgoing
/// text rewritten — via <see cref="MssqlQueryMasker"/> — before being forwarded, so the real SQL
/// Server itself computes and encodes the already-masked value. Everything else about the message
/// (and every message that doesn't touch a masked field at all) is still a pure, unmodified relay.
/// This replaced an earlier design (MssqlTranslatedSession, now removed) that decoded every row and
/// re-encoded its own TDS response by hand — that approach had to also fabricate its own LOGINACK
/// and guess every column's wire type, which kept drifting from what the real backend actually
/// sends (see CLAUDE.md for the LOGINACK version-mismatch bug that motivated dropping it).
///
/// Besides that, the only other thing done is peeking at SqlBatch/RPC text (via the same
/// SqlBatch.ParseSqlText/RpcRequest helpers SybaseClientSession uses) to write one line to the
/// shared IQueryComparisonLog — the "meeting point" — so it can be compared later against what
/// the Sybase proxy did for the same SQL.
/// </summary>
public sealed class MssqlPassthroughSession
{
    private readonly TcpClient _client;
    private readonly MssqlBackendOptions _backendOptions;
    private readonly string _proxyName;
    private readonly IQueryComparisonLog _comparisonLog;
    private readonly ILogger<MssqlPassthroughSession> _logger;
    private readonly object? _remote;
    private readonly IReadOnlyList<MaskedField> _maskedFields;

    public MssqlPassthroughSession(
        TcpClient client,
        MssqlBackendOptions backendOptions,
        string proxyName,
        IQueryComparisonLog comparisonLog,
        ILogger<MssqlPassthroughSession> logger,
        IReadOnlyList<MaskedField>? maskedFields = null)
    {
        _client = client;
        _backendOptions = backendOptions;
        _proxyName = proxyName;
        _comparisonLog = comparisonLog;
        _logger = logger;
        _remote = client.Client.RemoteEndPoint;
        _maskedFields = maskedFields ?? Array.Empty<MaskedField>();
    }

    public async Task RunAsync(CancellationToken ct)
    {
        using var _ = _client;
        await using var clientStream = _client.GetStream();
        var clientTds = new TdsStream(clientStream);

        using var backendClient = new TcpClient();
        await backendClient.ConnectAsync(_backendOptions.Server, _backendOptions.Port, ct);
        await using var backendStream = backendClient.GetStream();
        var backendTds = new TdsStream(backendStream);

        try
        {
            while (true)
            {
                var (type, payload) = await clientTds.ReadMessageAsync(ct);
                if (type == 0) return; // client disconnected cleanly
                _logger.LogDebug("[{Remote}] Mensaje recibido. Type=0x{Type:X2} Len={Len}", _remote, type, payload.Length);

                // See PreLogin.ForceEncryptionNotSupported — the one deliberate byte-level
                // exception to "relay everything unmodified", needed so the client never starts a
                // raw TLS handshake this message-oriented relay can't parse.
                if (type == TdsPacketType.PreLogin)
                    payload = PreLogin.ForceEncryptionNotSupported(payload);

                var (outType, outPayload, sql) = ApplyMaskingIfNeeded(type, payload);

                var stopwatch = Stopwatch.StartNew();
                await backendTds.WriteMessageAsync(outType, outPayload, ct);
                var (responseType, responsePayload) = await backendTds.ReadMessageAsync(ct);
                if (responseType == TdsPacketType.TabularResult && type == TdsPacketType.PreLogin)
                    responsePayload = PreLogin.ForceEncryptionNotSupported(responsePayload);
                await clientTds.WriteMessageAsync(responseType, responsePayload, ct);

                if (sql is not null)
                    _comparisonLog.Record(_proxyName, sql, responsePayload.Length, stopwatch.Elapsed);
            }
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException or SocketException)
        {
            _logger.LogInformation("Sesión passthrough {Remote} terminó: {Message}", _remote, ex.Message);
        }
    }

    private static string? ExtractSqlText(byte type, byte[] payload) => type switch
    {
        TdsPacketType.SqlBatch => SqlBatch.ParseSqlText(payload),
        TdsPacketType.Rpc => RpcRequest.TryGetExecSqlText(payload),
        _ => null,
    };

    // Returns what to actually forward (possibly rewritten) plus the SQL text for the comparison
    // log. An RPC call that needs rewriting is sent on as a plain SqlBatch instead (same ALL_HEADERS
    // prefix carried over via SqlBatch.BuildPayload) — RpcRequest.TryGetExecSqlText already resolved
    // every bound parameter to a literal in the extracted text, so the batch is self-contained and
    // doesn't need sp_executesql's parameter binding to run correctly.
    private (byte Type, byte[] Payload, string? Sql) ApplyMaskingIfNeeded(byte type, byte[] payload)
    {
        var sql = ExtractSqlText(type, payload);
        if (sql is null || _maskedFields.Count == 0) return (type, payload, sql);

        var rewritten = MssqlQueryMasker.Apply(sql, _maskedFields);
        if (rewritten == sql) return (type, payload, sql);

        _logger.LogDebug("[{Remote}] Enmascarando en el texto antes de reenviar. Original={Original} | Reenviado={Rewritten}", _remote, sql, rewritten);
        return (TdsPacketType.SqlBatch, SqlBatch.BuildPayload(payload, rewritten), rewritten);
    }
}
