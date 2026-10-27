using System.Diagnostics;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using AdoNetCore.AseClient;
using SQLProxy.Tds;

namespace SQLProxy;

/// <summary>
/// Owns one client TCP connection end to end: TDS handshake (PRELOGIN + LOGIN7), then a loop of
/// SQLBatch requests, each executed against a single dedicated AseConnection and translated back
/// into a TDS tabular result. One AseConnection per session (not per query) so ASE-session-scoped
/// state (temp tables, @@identity, SET options) behaves the way a client expects.
///
/// Was named "ClientSession" before this project grew a second proxy kind (MssqlPassthroughSession)
/// — renamed to make the two exist side by side without ambiguity.
///
/// Doesn't log into ASE with a fixed account anymore (2026-10-27) — the user/password actually used
/// against ASE come from the client's own LOGIN7 (<see cref="Login7.TryGetCredentials"/>), so the
/// "Sybase" proxy config only needs Server/Port, same shape as MssqlPassthrough. Windows/Integrated
/// auth (no plain password in LOGIN7) isn't supported — ASE doesn't understand it either.
/// </summary>
public sealed class SybaseClientSession
{
    private readonly TcpClient _client;
    private readonly AseBackendOptions _aseOptions;
    private readonly string _proxyName;
    private readonly IQueryComparisonLog _comparisonLog;
    private readonly ILogger<SybaseClientSession> _logger;
    private readonly object? _remote;
    private readonly IReadOnlyList<MaskedField> _maskedFields;

    // Zero = "no active client-driven transaction" (MS-TDS convention) — set to a real, non-zero
    // value by a BEGIN TRANSACTION Transaction Manager Request and cleared back to zero on
    // COMMIT/ROLLBACK. Only meaningful within this one session/connection; doesn't need to be
    // globally unique, just non-zero and distinguishable from "none".
    private byte[] _txDescriptor = new byte[8];
    private static long _txCounter;

    public SybaseClientSession(
        TcpClient client,
        AseBackendOptions aseOptions,
        string proxyName,
        IQueryComparisonLog comparisonLog,
        ILogger<SybaseClientSession> logger,
        IReadOnlyList<MaskedField>? maskedFields = null)
    {
        _client = client;
        _aseOptions = aseOptions;
        _proxyName = proxyName;
        _comparisonLog = comparisonLog;
        _logger = logger;
        _remote = client.Client.RemoteEndPoint;
        _maskedFields = maskedFields ?? Array.Empty<MaskedField>();
    }

    public async Task RunAsync(CancellationToken ct)
    {
        var remote = _remote;
        using var _ = _client;
        await using var networkStream = _client.GetStream();
        var tds = new TdsStream(networkStream);

        try
        {
            if (!await DoPreLoginAsync(tds, ct)) return;
            var login = await DoLoginAsync(tds, ct);
            if (login is null) return;
            var (requestedDatabase, userName, password) = login.Value;

            if (string.IsNullOrEmpty(userName))
            {
                // No username to extract means the client used Windows/Integrated auth (an SSPI
                // token instead of a plain LOGIN7 password) — there's nothing to forward to ASE,
                // which doesn't understand Windows auth either.
                _logger.LogWarning("[{Remote}] Login sin usuario SQL — este proxy necesita autenticación SQL (usuario y password) real para loguear contra ASE con esas mismas credenciales.", remote);
                await SendLoginFailureAsync(tds, "se requiere autenticación SQL (usuario y password) — este proxy usa las credenciales del login para conectarse a ASE, no soporta Windows/Integrated auth.", ct);
                return;
            }

            AseConnection ase;
            try
            {
                ase = await OpenAseConnectionAsync(MapToRealAseDatabase(requestedDatabase), userName, password, ct);
            }
            catch (Exception ex) when (ex is not (IOException or OperationCanceledException or SocketException))
            {
                // A raw disconnect here reads to the client as "connection reset mid-login" with no
                // useful message (that's exactly what happened before this was added — see
                // CLAUDE.md, "Bug real encontrado..."). Send a proper TDS login failure instead.
                _logger.LogWarning(ex, "Falló el login contra ASE para la sesión {Remote}", remote);
                await SendLoginFailureAsync(tds, ex.Message, ct);
                return;
            }

            await using (ase)
            {
                await SendLoginAckAsync(tds, requestedDatabase, ct);
                await RunBatchLoopAsync(tds, ase, ct);
            }
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException or SocketException)
        {
            _logger.LogInformation("Sesión {Remote} terminó: {Message}", remote, ex.Message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error no manejado en la sesión {Remote}", remote);
        }
    }

    private static async Task<bool> DoPreLoginAsync(TdsStream tds, CancellationToken ct)
    {
        var (type, payload) = await tds.ReadMessageAsync(ct);
        if (type != TdsPacketType.PreLogin) return false;

        var response = PreLogin.BuildResponse(payload);
        await tds.WriteMessageAsync(TdsPacketType.TabularResult, response, ct);
        return true;
    }

    private static async Task<(string Database, string UserName, string Password)?> DoLoginAsync(TdsStream tds, CancellationToken ct)
    {
        var (type, payload) = await tds.ReadMessageAsync(ct);
        if (type != TdsPacketType.Login7) return null;

        var database = Login7.TryGetRequestedDatabase(payload) is { Length: > 0 } db ? db : "master";
        var (userName, password) = Login7.TryGetCredentials(payload);
        return (database, userName, password);
    }

    // msdb is a pure MSSQL system database (SQL Agent jobs, Database Mail, Policy-Based
    // Management, SSIS...) — ASE has no equivalent at all, not even an empty shell. Creating a
    // real, permanently-empty "msdb" database in ASE just so this LOGIN doesn't fail was tried and
    // worked, but it's unnecessary real state in the backend for a database that will never have
    // actual content (see CLAUDE.md bug #24). Redirect to "master" instead: the client still
    // believes it's in "msdb" (the LOGINACK/ENVCHANGE below reports back whatever name it asked
    // for), but every query actually runs against ASE's real master database.
    private static string MapToRealAseDatabase(string requested) =>
        string.Equals(requested, "msdb", StringComparison.OrdinalIgnoreCase) ? "master" : requested;

    private async Task<AseConnection> OpenAseConnectionAsync(string database, string userName, string password, CancellationToken ct)
    {
        var connection = new AseConnection(_aseOptions.BuildConnectionString(database, userName, password));
        await connection.OpenAsync(ct);
        return connection;
    }

    // Order and exact token set verified byte-for-byte against a real SQL Server's LOGIN response
    // (via the mssql-passthrough proxy's comparison log — see CLAUDE.md bug #35): the
    // Database/Collation/Language ENVCHANGEs and their INFO companions come BEFORE the LOGINACK
    // token itself, then PacketSize ENVCHANGE and FEATUREEXTACK come after it. We used to send
    // only EnvChange(Database) + LoginAck + FeatureExtAck + Done — missing Collation, Language,
    // PacketSize, and both INFO messages entirely, on every single connection from the very first
    // message. Prime suspect for the deferred, client-side-only TdsExecuteRPC crash blocking
    // Object Explorer.
    private static async Task SendLoginAckAsync(TdsStream tds, string database, CancellationToken ct)
    {
        var writer = new TokenWriter();
        writer.WriteEnvChangeDatabase(database, database);
        writer.WriteInfo(5701, $"Changed database context to '{database}'.", "SQLProxy");
        writer.WriteEnvChangeCollation(CollationBytes.SqlLatin1GeneralCp1CiAs, Array.Empty<byte>());
        writer.WriteEnvChangeLanguage("us_english", "");
        writer.WriteInfo(5703, "Changed language setting to us_english.", "SQLProxy");
        writer.WriteLoginAck("SQLProxy");
        writer.WriteEnvChangePacketSize("4096", "4096");
        writer.WriteEmptyFeatureExtAck();
        writer.WriteDone(DoneStatus.Final, 0);
        await tds.WriteMessageAsync(TdsPacketType.TabularResult, writer.ToArray(), ct);
    }

    // Error numbers below 50000 collide with real SQL Server's own built-in error catalog — SMO/SSMS
    // dialogs always show the number, so giving each of our OWN synthetic error paths a distinct
    // one (50001+, never reused) means the user can paste a dialog and we know exactly which code
    // path produced it without grepping logs first. Errors ASE itself throws, forwarded as-is via
    // AseAsErrorNumber below, keep ASE's own real number instead — that's diagnostic information
    // ASE already generated, not ours to renumber.
    private const int LoginFailedErrorNumber = 50001;
    private const int UnsupportedRpcErrorNumber = 50002;
    private const int AseExecutionErrorNumber = 50003;

    private static async Task SendLoginFailureAsync(TdsStream tds, string message, CancellationToken ct)
    {
        var writer = new TokenWriter();
        writer.WriteError(LoginFailedErrorNumber, $"SQLProxy: no se pudo abrir la conexión contra ASE — {message}", "SQLProxy");
        writer.WriteDone(DoneStatus.Error, 0);
        await tds.WriteMessageAsync(TdsPacketType.TabularResult, writer.ToArray(), ct);
    }

    private async Task RunBatchLoopAsync(TdsStream tds, AseConnection ase, CancellationToken ct)
    {
        while (true)
        {
            var (type, payload) = await tds.ReadMessageAsync(ct);
            _logger.LogDebug("[{Remote}] Mensaje recibido. Type=0x{Type:X2} Len={Len}", _remote, type, payload.Length);
            if (type == 0) return; // client disconnected cleanly

            byte[] response;
            switch (type)
            {
                case TdsPacketType.SqlBatch:
                    var batchSql = SqlBatch.ParseSqlText(payload);
                    _logger.LogDebug("[{Remote}] RECIBIDO (SqlBatch). SQL={Sql}", _remote, batchSql);
                    response = await RunAndRecordAsync(ase, batchSql, ct);
                    break;

                case TdsPacketType.Rpc:
                    var sql = RpcRequest.TryGetExecSqlText(payload);
                    if (sql is not null)
                    {
                        _logger.LogDebug("[{Remote}] RECIBIDO (RPC/sp_executesql). SQL={Sql}", _remote, sql);
                        response = await RunAndRecordAsync(ase, sql, ct);
                    }
                    else
                    {
                        // This used to be a silent blind spot — a named-procedure RPC call (e.g.
                        // the ODBC catalog procs sp_tables/sp_databases/sp_columns) returns null
                        // from TryGetExecSqlText and went straight to an unlogged error response.
                        // See CLAUDE.md bug #23.
                        _logger.LogDebug("[{Remote}] RPC no soportado: {Description}", _remote, RpcRequest.Describe(payload));
                        response = BuildUnsupportedRpcResponse();
                    }
                    break;

                case TdsPacketType.Attention:
                    var ack = new TokenWriter();
                    ack.WriteDone(DoneStatus.Attention, 0);
                    await tds.WriteMessageAsync(TdsPacketType.TabularResult, ack.ToArray(), ct);
                    continue;

                case TdsPacketType.TransactionManager:
                    response = await HandleTransactionManagerRequestAsync(payload, ase, ct);
                    break;

                default:
                    _logger.LogWarning("Tipo de mensaje TDS {Type:X2} no soportado todavía — se ignora.", type);
                    continue;
            }

            await tds.WriteMessageAsync(TdsPacketType.TabularResult, response, ct);
        }
    }

    // MS-TDS 2.2.6.8 Transaction Manager Request — how SSMS/SqlClient run BEGIN/COMMIT/ROLLBACK
    // TRANSACTION when driven through the client API (SqlConnection.BeginTransaction(), and what
    // SSMS's "New Table" designer uses internally to wrap its CREATE TABLE) instead of sending
    // "BEGIN TRAN" as literal SQL text. Found 2026-10-27 via "New Table" silently never creating
    // anything: this message type was being logged-and-ignored with no response at all, leaving the
    // client waiting forever for an acknowledgment that never came.
    //
    // Wire shape: ALL_HEADERS (4-byte TotalLength + header data, usually just a transaction-
    // descriptor header we don't need to parse — the TMReqType immediately follows at offset
    // TotalLength) then a 2-byte TMReqType. BEGIN additionally carries an isolation level byte and a
    // B_VARCHAR transaction name we don't need either, since we only ever have one real transaction
    // per session and don't implement named/nested transactions or savepoints.
    private async Task<byte[]> HandleTransactionManagerRequestAsync(byte[] payload, AseConnection ase, CancellationToken ct)
    {
        const ushort TmBeginXact = 5, TmCommitXact = 7, TmRollbackXact = 8;

        var allHeadersLength = BitConverter.ToUInt32(payload, 0);
        var reqType = BitConverter.ToUInt16(payload, (int)allHeadersLength);

        var writer = new TokenWriter();
        try
        {
            switch (reqType)
            {
                case TmBeginXact:
                    await ExecuteTransactionCommandAsync(ase, "BEGIN TRANSACTION", ct);
                    _txDescriptor = BitConverter.GetBytes(Interlocked.Increment(ref _txCounter));
                    writer.WriteEnvChangeTransaction(EnvChangeType.BeginTransaction, _txDescriptor, Array.Empty<byte>());
                    writer.WriteDone(DoneStatus.Final, 0);
                    _logger.LogDebug("[{Remote}] Transaction Manager: BEGIN TRANSACTION (real contra ASE).", _remote);
                    break;

                case TmCommitXact:
                    await ExecuteTransactionCommandAsync(ase, "COMMIT TRANSACTION", ct);
                    writer.WriteEnvChangeTransaction(EnvChangeType.CommitTransaction, Array.Empty<byte>(), _txDescriptor);
                    _txDescriptor = new byte[8];
                    writer.WriteDone(DoneStatus.Final, 0);
                    _logger.LogDebug("[{Remote}] Transaction Manager: COMMIT TRANSACTION (real contra ASE).", _remote);
                    break;

                case TmRollbackXact:
                    await ExecuteTransactionCommandAsync(ase, "ROLLBACK TRANSACTION", ct);
                    writer.WriteEnvChangeTransaction(EnvChangeType.RollbackTransaction, Array.Empty<byte>(), _txDescriptor);
                    _txDescriptor = new byte[8];
                    writer.WriteDone(DoneStatus.Final, 0);
                    _logger.LogDebug("[{Remote}] Transaction Manager: ROLLBACK TRANSACTION (real contra ASE).", _remote);
                    break;

                default:
                    // SAVE_XACT / PROPAGATE_XACT / PROMOTE_XACT / GET_DTC_ADDRESS — distributed-
                    // transaction/savepoint territory this proxy doesn't implement. Ack with a bare
                    // DONE instead of hanging; this proxy was never going to support MSDTC anyway.
                    _logger.LogWarning("[{Remote}] Transaction Manager: TMReqType {ReqType} no soportado — se confirma sin hacer nada.", _remote, reqType);
                    writer.WriteDone(DoneStatus.Final, 0);
                    break;
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug("[{Remote}] Transaction Manager FALLÓ contra ASE. TMReqType={ReqType} | Error={Error}", _remote, reqType, ex.Message);
            writer = new TokenWriter();
            writer.WriteError(AseExecutionErrorNumber, ex.Message, "SQLProxy");
            writer.WriteDone(DoneStatus.Error, 0);
        }
        return writer.ToArray();
    }

    private static async Task ExecuteTransactionCommandAsync(AseConnection ase, string sql, CancellationToken ct)
    {
        using var cmd = new AseCommand(sql, ase);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    private async Task<byte[]> RunAndRecordAsync(AseConnection ase, string sql, CancellationToken ct)
    {
        var stopwatch = Stopwatch.StartNew();
        var response = await ExecuteBatchAsync(ase, sql, ct);
        _comparisonLog.Record(_proxyName, sql, response.Length, stopwatch.Elapsed);
        return response;
    }

    private async Task<byte[]> ExecuteBatchAsync(AseConnection ase, string sql, CancellationToken ct)
    {
        var probeResponse = await SsmsProbes.TryHandleAsync(sql, ase, ct);
        if (probeResponse is not null)
        {
            // No "ENTREGADO" line here on purpose — a probe match never touches ASE at all, there's
            // no second SQL text to compare against. If the FABRICATED response itself is wrong,
            // that's a probe bug, not a received-vs-delivered discrepancy.
            _logger.LogDebug("[{Remote}] PROBE MATCHEÓ (respuesta fabricada, no llega a ASE). SQL={Sql}", _remote, sql);
            return probeResponse;
        }

        var writer = new TokenWriter();
        try
        {
            var normalizedSql = TrimTrailingSemicolon(NormalizeOnPrimaryFilegroup(NormalizeParenthesizedTop(NormalizeBracketedTempTableNames(sql))));
            if (normalizedSql != sql)
                _logger.LogDebug("[{Remote}] ENTREGADO a ASE (normalizado, distinto de lo recibido). SQL={Sql}", _remote, normalizedSql);

            using var cmd = new AseCommand(normalizedSql, ase);
            using var reader = (AseDataReader)await cmd.ExecuteReaderAsync(ct);

            var maskedColumns = ResolveMaskedColumns(normalizedSql);
            if (maskedColumns.Count > 0)
                _logger.LogDebug("[{Remote}] Enmascarando columnas: {Columns}", _remote,
                    string.Join(", ", maskedColumns.Select(kv => $"{kv.Key} ({kv.Value.Type})")));

            bool hasMore;
            do
            {
                var fieldCount = reader.FieldCount;
                List<ProxyColumn>? columns = null;
                var rowsInResult = 0UL;

                if (fieldCount > 0)
                {
                    columns = AseResultMapper.BuildColumns(reader, maskedColumns);
                    writer.WriteColumnMetadata(columns);
                    while (await reader.ReadAsync(ct))
                    {
                        writer.WriteRow(columns, AseResultMapper.ReadRowValues(reader, fieldCount, maskedColumns));
                        rowsInResult++;
                    }
                }

                var recordsAffected = reader.RecordsAffected;
                hasMore = await reader.NextResultAsync(ct);

                // RecordsAffected == -1 means "not applicable" (e.g. SET statements) — real SQL
                // Server doesn't claim a valid row count in that case, it just sends DONE_FINAL/MORE
                // with no DONE_COUNT bit. Claiming COUNT with a bogus 0 here is what was tripping up
                // the ODBC 17 driver (silent abort right after the first session-setup SET statement).
                var countIsValid = columns is not null || recordsAffected >= 0;
                var rowCount = columns is not null ? rowsInResult : (ulong)Math.Max(recordsAffected, 0);
                var status = (hasMore ? DoneStatus.More : DoneStatus.Final) | (countIsValid ? DoneStatus.Count : 0);
                writer.WriteDone(status, rowCount);
            } while (hasMore);
        }
        catch (Exception ex) when (sql.TrimStart().StartsWith("SET ", StringComparison.OrdinalIgnoreCase)
            && (ex.Message.Contains("is not a recognized SET command", StringComparison.OrdinalIgnoreCase)
                || ex.Message.Contains("is not a recognized option", StringComparison.OrdinalIgnoreCase)))
        {
            // SqlClient's connection-open sequence (used by SSMS/SMO too) sends a bundle of MSSQL
            // SET statements ASE just doesn't have (LOCK_TIMEOUT, CONCAT_NULL_YIELDS_NULL, and
            // friends — there may be more than one, and ASE phrases the rejection differently
            // depending on which one: "not a recognized SET command" for some, "not a recognized
            // option" for others). There's nothing to actually apply on the ASE side; ack success
            // instead of surfacing ASE's parse error, same reasoning as the sp_configure no-op in
            // SsmsProbes. Guarded on the batch actually being a SET, not just any "not a
            // recognized ..." message, so an unrelated real error doesn't get swallowed here too.
            writer = new TokenWriter();
            writer.WriteDone(DoneStatus.Final, 0);
        }
        catch (Exception ex)
        {
            // Keep this at Debug, not swallowed — every SSMS probe we didn't know about yet (see
            // SsmsProbes.cs) first showed up as a confusing client-side error with no way to tell
            // what SQL actually caused it without this.
            _logger.LogDebug("[{Remote}] FALLÓ contra ASE (ni probe ni normalización lo resolvieron). SQL={Sql} | Error={Error}", _remote, sql, ex.Message);
            writer = new TokenWriter();
            writer.WriteError(AseExecutionErrorNumber, ex.Message, "SQLProxy");
            writer.WriteDone(DoneStatus.Error, 0);
        }

        return writer.ToArray();
    }

    // SMO's replication enumeration (Publications/Subscriptions, tried per-database — see
    // CLAUDE.md bug #38) creates working temp tables with bracket-quoted names like
    // "[#unify_temptbl63928566716308.5]". ASE's parser rejects brackets around a '#'-prefixed
    // identifier outright ("is illegal because its first character is '#', which is ambiguous")
    // — not a missing-feature gap, a pure syntax mismatch: ASE's own unquoted "#name" temp-table
    // syntax (already used successfully elsewhere, e.g. #SVer, #tmp_sp_get_sqlagent_properties)
    // works fine, MSSQL's square-bracket quoting just isn't something ASE's grammar accepts at
    // all. Stripping the brackets lets the real temp table mechanics do their job instead of
    // forwarding a guaranteed syntax error that SMO doesn't handle gracefully downstream.
    private static readonly Regex BracketedTempTableNameRegex = new(@"\[(#[^\]]+)\]", RegexOptions.Compiled);

    private static string NormalizeBracketedTempTableNames(string sql) =>
        BracketedTempTableNameRegex.Replace(sql, "$1");

    // MSSQL's "TOP (n)" (parenthesized form, what SSMS's "Select Top N Rows" generates —
    // 2026-10-27) isn't valid ASE syntax: ASE's grammar only knows the bare "TOP n" form (no
    // parens), and misreads the "(" as the start of a function call — "Function 'TOP' not found."
    // Stripping just the parens around the row count is safe and semantically identical in both
    // dialects; ASE's TOP already accepts a plain integer the same way MSSQL's does.
    private static readonly Regex ParenthesizedTopRegex = new(@"\bTOP\s*\(\s*(\d+)\s*\)", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static string NormalizeParenthesizedTop(string sql) =>
        ParenthesizedTopRegex.Replace(sql, "TOP $1");

    // MSSQL's "ON [PRIMARY]" filegroup clause (what SSMS's "New Table" designer appends to every
    // generated CREATE TABLE, 2026-10-27) isn't valid ASE syntax either — ASE has "segments", not
    // filegroups, and no segment is ever named "PRIMARY" by default ("Segment 'PRIMARY' does not
    // exist."). This proxy's own filegroup probe (BuildFilegroupListProbeResponse) only ever reports
    // the one fake "PRIMARY" filegroup, so this is the only value the clause can ever take — safe to
    // strip outright rather than trying to map it to a real ASE segment name.
    private static readonly Regex OnPrimaryFilegroupRegex = new(@"\s+ON\s+\[?PRIMARY\]?", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static string NormalizeOnPrimaryFilegroup(string sql) =>
        OnPrimaryFilegroupRegex.Replace(sql, "");

    // Per-proxy field masking (CLAUDE.md, 2026-10-27) — see MaskedFieldResolver (shared with
    // MssqlQueryMasker, same resolution logic regardless of which engine answers the query or how
    // the masking is actually applied).
    private Dictionary<string, MaskedField> ResolveMaskedColumns(string sql) =>
        MaskedFieldResolver.Resolve(sql, _maskedFields);

    // ASE rejects a lone trailing ";" with no statement after it ("Incorrect syntax near ';'.") —
    // found via the "New Table" designer, which sends a bare "use [Banksys];" as its own batch
    // (2026-10-26). MSSQL/T-SQL tolerates a dangling terminator; ASE's grammar doesn't. Trimming
    // just the one trailing semicolon (plus surrounding whitespace) is safe for every batch, not
    // only "use" ones — a semicolon used as a mid-batch statement SEPARATOR is untouched, only a
    // trailing one with nothing after it is ever removed.
    private static string TrimTrailingSemicolon(string sql)
    {
        var trimmed = sql.TrimEnd();
        return trimmed.EndsWith(';') ? trimmed[..^1] : sql;
    }

    private static byte[] BuildUnsupportedRpcResponse()
    {
        var writer = new TokenWriter();
        writer.WriteError(UnsupportedRpcErrorNumber,
            "SQLProxy: solo se soporta RPC hacia sp_executesql con un único parámetro @statement de texto (sin parámetros adicionales ligados). Usar una consulta SQL literal.",
            "SQLProxy");
        writer.WriteDone(DoneStatus.Error, 0);
        return writer.ToArray();
    }
}
