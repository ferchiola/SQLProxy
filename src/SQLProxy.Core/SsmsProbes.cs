using AdoNetCore.AseClient;
using SQLProxy.Tds;

namespace SQLProxy;

/// <summary>
/// SSMS (and SMO-based tools in general) run a handful of fixed "what kind of server is this"
/// discovery scripts right after connecting — edition/version/platform, admin-connection/SMO
/// capability checks, etc. These use MSSQL-only system functions/views
/// (<c>SERVERPROPERTY</c>, <c>@@MICROSOFTVERSION</c>, <c>sys.dm_os_host_info</c>,
/// <c>sys.endpoints</c>, <c>sys.dm_exec_connections</c>...) that simply don't exist in Sybase/ASE.
/// There's no "real" answer to forward — this isn't a protocol bug, it's a semantic gap between
/// the two engines. Each probe below is matched by a fingerprint specific enough not to collide
/// with a real user query, and answered with a fabricated-but-plausible response instead of
/// letting it hit ASE and fail with a confusing syntax/undeclared-variable error.
///
/// Known limitation: this only covers the probes that block the initial connection. SSMS's Object
/// Explorer, IntelliSense, and property panels run many more catalog queries that aren't
/// intercepted here — see the project CLAUDE.md.
/// </summary>
internal static class SsmsProbes
{
    // Collapses all whitespace runs (including \r\n vs \n differences) to single spaces — lets a
    // fingerprint compare against a known-exact query with "==" instead of a substring Contains(),
    // which is how bug #40 happened: the Contains("suser_sname") probe below used to also match
    // the (structurally unrelated) SQL Agent properties script, because that script happens to
    // call suser_sname(...) once near the end — Contains() can't tell "this IS the suser_sname
    // query" from "this HAPPENS TO MENTION suser_sname". Exact-match on normalized text can't make
    // that mistake. Used for every probe below where the real client text is fully known and
    // fixed; probes matching genuinely variable text (a bound parameter, a configuration_id) still
    // need Contains()/regex — see the comment on each.
    private static readonly System.Text.RegularExpressions.Regex WhitespaceRegex = new(@"\s+");

    private static string Normalize(string sql) => WhitespaceRegex.Replace(sql, " ").Trim();

    private static bool IsExactly(string sql, string knownExactNormalized) =>
        Normalize(sql).Equals(knownExactNormalized, StringComparison.OrdinalIgnoreCase);

    // Matches by the FULL SET of "AS [Alias]" column aliases a query declares, instead of a single
    // substring — see CLAUDE.md bug #44. Three separate real queries (#39/#36/#43) all share the
    // literal text "master.sys.databases AS dtb", and Contains()-based fingerprints kept picking
    // the wrong one of the three depending on registration order, each time in a new way (first
    // losing 4 of 12 columns, then returning 0 rows, then returning 0 columns and crashing the
    // client). The full alias set is effectively a structural fingerprint: none of this project's
    // real captured queries share an identical one, so collisions become structurally much harder
    // instead of needing yet another hand-tuned Contains() combination per new query shape found.
    private static readonly System.Text.RegularExpressions.Regex AllAliasesRegex =
        new(@"\[(\w+)\]", System.Text.RegularExpressions.RegexOptions.Compiled);

    private static HashSet<string> ExtractAliasSet(string sql) =>
        AllAliasesRegex.Matches(sql).Select(m => m.Groups[1].Value).ToHashSet(StringComparer.OrdinalIgnoreCase);

    private static bool HasExactAliases(string sql, params string[] expectedAliases) =>
        ExtractAliasSet(sql).SetEquals(expectedAliases);

    // Real client text captured byte-for-byte via the mssql-passthrough proxy's comparison log
    // (2026-10-25) — see CLAUDE.md bug #40. Pre-normalized (single-spaced) so IsExactly doesn't
    // have to re-derive it from a \r\n-laden literal every call.
    private const string EditionScriptExact =
        "DECLARE @edition sysname; SET @edition = cast(SERVERPROPERTY(N'EDITION') as sysname); " +
        "SELECT case when @edition = N'SQL Azure' then 2 else 1 end as 'DatabaseEngineType', " +
        "SERVERPROPERTY('EngineEdition') AS DatabaseEngineEdition, SERVERPROPERTY('ProductVersion') AS ProductVersion, " +
        "@@MICROSOFTVERSION AS MicrosoftVersion; select host_platform from sys.dm_os_host_info if @edition = N'SQL Azure' " +
        "select 'TCP' as ConnectionProtocol else exec ('select CONVERT(nvarchar(40),CONNECTIONPROPERTY(''net_transport'')) as ConnectionProtocol')";

    private const string AdminConnectionScriptExact =
        "IF (@@microsoftversion / 0x01000000) >= 9 AND ISNULL(IS_SRVROLEMEMBER(N'sysadmin'), 0) = 1 BEGIN " +
        "SELECT se.is_admin_endpoint AS N'AdminConnection', (SELECT CAST(cfg.value AS bit) AS [ConfigValue] FROM sys.configurations AS cfg WHERE configuration_id=16387) AS N'SmoEnabled' " +
        "FROM sys.endpoints se INNER JOIN sys.dm_exec_connections dmc ON dmc.endpoint_id = se.endpoint_id WHERE dmc.session_id = @@spid END ELSE BEGIN " +
        "IF (@@microsoftversion / 0x01000000) >= 9 BEGIN SELECT CAST(0 AS BIT) AS N'AdminConnection', " +
        "(SELECT CAST(cfg.value AS bit) AS [ConfigValue] FROM sys.configurations AS cfg WHERE configuration_id=16387) AS N'SmoEnabled' END ELSE BEGIN " +
        "SELECT CAST(0 AS BIT) AS N'AdminConnection', CAST(0 AS BIT) AS N'SmoEnabled' END END";

    // Build functions take (sql, ase, ct) — most ignore ase/ct and just fabricate a plausible
    // answer, but a few (BuildDatabaseListProbeResponse) query ASE for the real equivalent data
    // instead of making something up, when ASE actually has one.
    private static readonly (Func<string, bool> Matches, Func<string, AseConnection, CancellationToken, Task<byte[]>> Build)[] Probes =
    {
        (sql => IsExactly(sql, EditionScriptExact), Sync(BuildEditionProbeResponse)),
        (sql => IsExactly(sql, AdminConnectionScriptExact), Sync(BuildAdminConnectionProbeResponse)),
        // Exact text captured via the comparison log: "select is_srvrolemember('sysadmin') * 1 +
        // is_srvrolemember('serveradmin') * 2 + ... + is_srvrolemember('bulkadmin') * 128" — a
        // single, fixed line, no bound/variable parts, safe to pin down fully instead of Contains().
        (sql => IsExactly(sql,
            "select is_srvrolemember('sysadmin') * 1 +is_srvrolemember('serveradmin') * 2 +is_srvrolemember('setupadmin') * 4 " +
            "+is_srvrolemember('securityadmin') * 8 +is_srvrolemember('processadmin') * 16 +is_srvrolemember('dbcreator') * 32 " +
            "+is_srvrolemember('diskadmin') * 64+ is_srvrolemember('bulkadmin') * 128"),
            BuildServerRoleBitmaskProbeResponse),
        // "select value_in_use from sys.configurations where configuration_id = N" — a single
        // scalar, used e.g. to check whether Agent XPs (16384) is on. MUST be registered BEFORE
        // the full-dump probe below: it also contains "sys.configurations" and was getting
        // wrongly swallowed by that one's Contains() fingerprint, which answers with the full
        // 95-row/9-column dump instead of the one int this query actually asked for — a
        // column-count AND type mismatch (first column is a string Name, not an int value_in_use)
        // that's the most likely cause of a client-side NullReferenceException/InvalidCastException
        // (see CLAUDE.md bug #25). Looks the id up in the same real dataset as the full dump.
        (sql => sql.Contains("value_in_use", StringComparison.OrdinalIgnoreCase)
                && sql.Contains("sys.configurations", StringComparison.OrdinalIgnoreCase),
            Sync(BuildConfigValueInUseProbeResponse)),
        (sql => sql.Contains("sys.configurations", StringComparison.OrdinalIgnoreCase), Sync(BuildConfigurationsProbeResponse)),
        (sql => sql.Contains("sp_configure", StringComparison.OrdinalIgnoreCase)
                || sql.Trim().StartsWith("RECONFIGURE", StringComparison.OrdinalIgnoreCase), Sync(BuildNoOpSuccessResponse)),
        // SMO's main "load full server properties" bootstrap script — a multi-statement batch
        // (temp table + xp_msver + sys.dm_os_host_info + a big final 15-column SELECT) that the
        // generic SERVERPROPERTY fallback below badly mishandled (it only grabbed the 5 columns
        // that were literal SERVERPROPERTY(...) calls, silently dropping the other 10 — literals,
        // computed expressions, other functions — causing a column-count/ordinal mismatch
        // downstream in SMO). Must be registered BEFORE the generic fallback.
        (sql => sql.Contains("xp_msver", StringComparison.OrdinalIgnoreCase), Sync(BuildFullServerPropertiesProbeResponse)),
        // ^ BuildFullServerPropertiesProbeResponse adapts its own column set based on which columns
        // the real query actually asked for (see CLAUDE.md bug #41) — SMO sends a DIFFERENT variant
        // of this same bootstrap script depending on claimed edition (e.g. [Server_Status] is
        // present for Standard, absent for Express), and a fixed hardcoded shape here caused the
        // exact "wrong type in wrong column" (string landing in an int-typed ordinal) class of bug
        // this whole project has repeatedly hit (#8/#17/#25) the moment the edition was changed.
        // A THIRD, even bigger SMO bootstrap script (~59 columns: AuditLevel, NumberOfLogFiles,
        // LoginMode, ..., ServerType) — found via "Select Top N Rows" throwing a client-side "value
        // passed in must be an enum base" error on ANY table, with nothing reaching this proxy at
        // all (2026-10-27): SMO reads this script's result once, caches it, and a later action
        // (query generation) reads one of its enum-backed properties — ServiceStartMode,
        // ClusterQuorumType/State, HadrManagerStatus, EngineEdition are all real SMO enums in this
        // exact column list — from a value that landed in the wrong ordinal. This script ALSO
        // contains both "[RootDirectory]" and "[IsPolyBaseInstalled]" (same two literal aliases as
        // the smaller 27-column script below), so it was being swallowed by that probe — 27 columns
        // answered for a 59-column request, the same silent column-count mismatch class as
        // #8/#17/#25, just one none of those fixes had actually hit yet. Fingerprint needs two
        // markers UNIQUE to this bigger script ([AuditLevel] + [ServerType], neither present in the
        // smaller one) — MUST be registered before it for the same reason bug #9 documents (the more
        // specific script has to win over one that merely shares a substring).
        (sql => sql.Contains("[AuditLevel]", StringComparison.OrdinalIgnoreCase)
                && sql.Contains("[ServerType]", StringComparison.OrdinalIgnoreCase), BuildFullServerBootstrapProbeResponse),
        // Another SMO bootstrap script, same bug class as the xp_msver one above: a big 27-column
        // SELECT (IsCaseSensitive, MaxPrecision, RootDirectory, Collation, ..., IsPolyBaseInstalled)
        // mostly built from SERVERPROPERTY(...) calls but also local variables (@MasterPath,
        // @ErrorLogPath, ...) and other expressions — the generic fallback below would only grab
        // the SERVERPROPERTY ones and silently drop the rest, corrupting the column count/order.
        // Must be registered BEFORE the generic fallback, same reasoning as xp_msver.
        (sql => sql.Contains("[RootDirectory]", StringComparison.OrdinalIgnoreCase)
                && sql.Contains("[IsPolyBaseInstalled]", StringComparison.OrdinalIgnoreCase), BuildServerRootPropertiesProbeResponse),
        // SUSER_SNAME() — current login name. We always log into ASE as "sa" regardless of what
        // the client claimed in LOGIN7, so that's the honest answer.
        //
        // CONFIRMED collision (2026-10-25, see CLAUDE.md bug #40), not just a theoretical risk:
        // this used to be Contains("suser_sname"), and the SQL Agent properties script (registered
        // much later in this list) also calls suser_sname(...) once, near its end
        // ("...suser_sname(sid_binary(ISNULL(@AgtGroup,N''))),N'')..."). Contains() let THIS probe
        // hijack that entire 28-column script and answer with a single "sa" scalar instead — the
        // SQL Agent probe never actually ran, no matter how correct its own logic was. Exact match
        // on the real, fixed, single-line query text closes this off structurally.
        (sql => IsExactly(sql, "select suser_sname()"), Sync(() => BuildScalarResponse("sa"))),
        // "select permissions(), is_member(N'db_owner')" — the "New Table" designer's permission
        // check right before letting the create go through (2026-10-27). ASE has no permissions()
        // function at all. We always log into ASE as "sa" (effectively unrestricted), so the honest
        // answer for is_member('db_owner') is 1 — and real SQL Server's own convention for
        // permissions() is to return -1 (all bits set) when the caller holds every permission on the
        // object, which is the same "unrestricted" case here. Two bare, unaliased int columns (no
        // AS in the real query, so the real column names would be empty too).
        (sql => IsExactly(sql, "select permissions(), is_member(N'db_owner')"),
            Sync(BuildPermissionsProbeResponse)),
        // "SELECT ISNULL(HAS_PERMS_BY_NAME(QUOTENAME(N'X', ']'), 'DATABASE', 'VIEW DATABASE
        // STATE'), -1)" — the last standing gap from the probe-coverage review (2026-10-27). ASE
        // has neither HAS_PERMS_BY_NAME nor QUOTENAME at all. Same reasoning as permissions()/
        // is_member('db_owner') above: we're always "sa" (unrestricted), so the honest answer to
        // "does this login have VIEW DATABASE STATE" is yes (1) — matches HAS_PERMS_BY_NAME's real
        // return convention (1=granted, 0=denied, NULL=invalid principal/securable, which is what
        // the query's own ISNULL(...,-1) guards against). Matches the whole
        // "HAS_PERMS_BY_NAME(QUOTENAME(" call shape generically rather than this one exact
        // permission literal, so any other permission name substituted into the same script shape
        // is covered too without needing a new probe each time.
        (sql => sql.Contains("HAS_PERMS_BY_NAME(QUOTENAME(", StringComparison.OrdinalIgnoreCase),
            Sync(() => BuildScalarResponse(1))),
        // Another, different "list databases this login can see" query — this one via
        // "SELECT dtb.name AS [Database] FROM master.dbo.sysdatabases dtb WHERE
        // (has_dbaccess(dtb.name) = 1)". MUST be registered BEFORE the standalone HAS_DBACCESS
        // probe below — it also contains the substring "has_dbaccess", and used to get hijacked by
        // that probe's old overly-broad fingerprint, which returned a single "False" scalar where
        // SMO expected a list of database names. The fallout was ugly: SMO then ran "use [False]"
        // as if that scalar were a database name — see CLAUDE.md bug #16. Real ASE equivalent
        // exists (master..sysdatabases again), so query it for real instead of faking anything —
        // same helper as BuildDatabaseListProbeResponse, just reported under a different column
        // name/shape. We're always "sa", so every real database counts as accessible.
        (sql => sql.Contains("master.dbo.sysdatabases", StringComparison.OrdinalIgnoreCase)
                && HasExactAliases(sql, "Database"), BuildAccessibleDatabaseListProbeResponse),
        // HAS_DBACCESS('db') as a bare standalone call (e.g. "select has_dbaccess('msdb')") — used
        // by SSMS/SMO to decide whether a given database can be opened/listed. No "AS [Alias]" in
        // this shape at all (bare scalar, no column name), so the alias-set matcher doesn't apply
        // here — anchored on the batch actually STARTING with this call instead (bug #16: a bare
        // Contains() here used to also match has_dbaccess(...) used inside a larger query).
        (sql => sql.TrimStart().StartsWith("select has_dbaccess(", StringComparison.OrdinalIgnoreCase),
            BuildHasDbAccessProbeResponse),
        // The whole "sys.databases AS dtb" family below was the source of three separate, confirmed
        // fingerprint collisions this session (#39/#36/#43 all sharing "master.sys.databases AS dtb"
        // as a bare substring — see CLAUDE.md bug #44 for the full story). Matching on each query's
        // COMPLETE alias set instead removes the ambiguity: none of these four real, captured shapes
        // share an identical set, so registration order no longer matters for correctness between
        // them (kept in a sensible order regardless, for readability).
        //
        // 1) "SELECT dtb.name AS [Name], dtb.state AS [State] FROM master.sys.databases dtb" — an
        //    older/simpler database-list shape (CLAUDE.md bug #14), not observed in real traffic
        //    during this session's final successful run but kept for safety.
        (sql => HasExactAliases(sql, "Name", "State")
                && sql.Contains("master.sys.databases", StringComparison.OrdinalIgnoreCase),
            BuildDatabaseListProbeResponse),
        // 2) "SELECT CAST(has_dbaccess(dtb.name) AS bit) AS [IsAccessible] FROM master.sys.databases
        //    AS dtb WHERE (dtb.name=N'Banksys')" — see CLAUDE.md bug #43.
        (sql => HasExactAliases(sql, "IsAccessible"), BuildDatabaseIsAccessibleProbeResponse),
        // 3) THE actual "populate the Databases node" query (CLAUDE.md bug #39) — 12 columns
        //    (Database_Name, Database_Urn, Database_Status, ...). Also reused for a single-database
        //    refresh (same 12 columns, "WHERE (dtb.name=N'Banksys')" instead of "dtb.name in (...)")
        //    — BuildUserDatabaseListProbeResponse detects which shape it got and filters accordingly.
        (sql => HasExactAliases(sql,
                "Database_Name", "Database_Urn", "Database_ContainmentType", "Database_RecoveryModel",
                "Database_Owner", "Database_Status", "Database_CompatibilityLevel", "Database_IsSqlDw",
                "RecoveryModel", "UserAccess", "ReadOnly", "Database_DatabaseName2"),
            BuildUserDatabaseListProbeResponse),
        // 4) "SELECT '' AS [DefaultSchema], dtb.name AS [DatabaseName] FROM master.sys.databases AS
        //    dtb WHERE (dtb.name=N'Banksys')" — SMO's "New Table" designer asks this to know which
        //    schema to qualify the generated CREATE TABLE with, before ever sending the CREATE
        //    itself. "dbo" is the honest default — same convention real SQL Server uses when no
        //    contained-user schema applies (CLAUDE.md bug #45). Registered before #5 below —
        //    same alias-set-is-unique reasoning.
        (sql => HasExactAliases(sql, "DefaultSchema", "DatabaseName"), BuildDatabaseDefaultSchemaProbeResponse),
        // 4.5) ANOTHER unfiltered "list every database" shape (6 columns: Name, ID, IsSystemObject,
        //    Collation, IsAccessible, DatabaseName2), found via the "New Table" designer's database
        //    picker (2026-10-26) — no "dtb.name=" filter at all, so it skipped every probe above
        //    (which all either need a WHERE filter or a different alias set) and fell through to
        //    real ASE execution, failing on "master.sys.databases not found". Real ASE data, same
        //    helper as every other database-list probe.
        (sql => HasExactAliases(sql, "Name", "ID", "IsSystemObject", "Collation", "IsAccessible", "DatabaseName2"),
            BuildDatabaseListWithIdsProbeResponse),
        // 5) Per-database property lookup (CLAUDE.md bug #36) — SMO's sp_executesql with a bound
        //    @_msparam_0 parameter (substituted to a literal by RpcRequest before this ever sees
        //    it). Gave up on enumerating every exact column-list variant by hand after the 4th
        //    distinct one showed up (CLAUDE.md bug #46) — back to a broad structural fingerprint
        //    ("FROM master.sys.databases AS dtb" + "dtb.name=", not a specific alias set), SAFE
        //    now that it's registered LAST in this family: every shape with its own quirk (a
        //    function call instead of a plain "dtb.X AS [Y]" column, a bespoke response shape) has
        //    its own dedicated probe ahead of this one. BuildDatabasePropertyLookupResponse's
        //    column-extraction regex already handles ANY combination of plain "dtb.X AS [Y]"
        //    columns generically — that's what actually needed to be broad, not the fingerprint.
        (sql => sql.Contains("master.sys.databases AS dtb", StringComparison.OrdinalIgnoreCase)
                && sql.Contains("dtb.name=", StringComparison.OrdinalIgnoreCase),
            BuildDatabasePropertyLookupResponse),
        // "SELECT CASE WHEN has_dbaccess(N'Banksys') = 1 THEN 'true' ELSE 'false' END" — yet another
        // has_dbaccess shape (no column alias at all this time, and wants the STRING 'true'/'false'
        // rather than a bit) — used by the "New Table" designer alongside the DefaultSchema probe
        // above (CLAUDE.md bug #45).
        (sql => HasDbAccessCaseRegex.IsMatch(sql), BuildDatabaseIsAccessibleCaseProbeResponse),
        // Policy-Based Management "PolicyStore" lookup — real text captured via Extended Events
        // against a genuine SQL Server (2026-10-25, see CLAUDE.md bug #30): reads
        // msdb.dbo.syspolicy_configuration for Enabled/HistoryRetentionInDays/LogOnSuccess. None of
        // that schema exists in ASE (msdb is redirected to master, which has nothing PBM-related).
        // Enabled=false means SMO treats Policy-Based Management as simply not configured — it
        // shouldn't go on to query syspolicy_system_health_state at all once this says so.
        (sql => sql.Contains("syspolicy_configuration", StringComparison.OrdinalIgnoreCase),
            Sync(BuildPolicyStoreProbeResponse)),
        // Policy health-state check ("case when 1=msdb.dbo.fn_syspolicy_is_automation_enabled() and
        // exists (select * from msdb.dbo.syspolicy_system_health_state ...) then 1 else 0 end AS
        // [PolicyHealthState]") — this is the literal query behind "Cannot display policy health
        // state... Permission to access the msdb database is required". Same no-PBM-schema problem
        // as above; answering 0 (unhealthy/not-applicable) is the honest answer either way.
        (sql => sql.Contains("PolicyHealthState", StringComparison.OrdinalIgnoreCase),
            Sync(() => BuildScalarResponse(0))),
        // Contained-Availability-Group session check ("IF OBJECT_ID(N'sys.sp_MSIsContainedAGSession',
        // N'P') IS NOT NULL BEGIN ... END ELSE SELECT 0") — same AlwaysOn/AG family as the xp_qv
        // probe, no real ASE equivalent. Answers with the ELSE branch's literal (0), which is what
        // a real non-AG server would return here too.
        (sql => sql.Contains("sp_MSIsContainedAGSession", StringComparison.OrdinalIgnoreCase),
            Sync(() => BuildScalarResponse(0))),
        // "Is this a contained-authentication database" check (compares db_id() to 1, i.e. "are we
        // in master") — fails on ASE because of the "use [master];"/trailing-semicolon syntax, not
        // because of anything we could usefully answer differently: we're never actually "in
        // master" in ASE's sense, but SMO just wants a 0/1 bit, and 0 (not contained auth) is the
        // correct answer for every database this proxy will ever expose.
        (sql => sql.Contains("resetting the context", StringComparison.OrdinalIgnoreCase), Sync(() => BuildScalarResponse(0))),
        // "SELECT CAST(COLLATIONPROPERTY(name, 'LCID') AS int) AS [LocaleID] FROM
        // sys.fn_helpcollations() cl WHERE (cl.name=N'cp850')" — SMO's "New Table" designer needs
        // this to populate the column-type grid's collation dropdown. ASE doesn't have
        // sys.fn_helpcollations (this has been failing silently in the debug log since early in
        // this session — see "Batch falló" entries for "cp850" — never blocking anything visible
        // until the New Table designer specifically needed it, 2026-10-26). "cp850" is ASE's real
        // charset name, not a real MSSQL collation, so there's no genuine LCID to look up — reusing
        // 1033 (en-US), the same LCID already baked into CollationBytes.SqlLatin1GeneralCp1CiAs sent
        // at LOGIN, keeps this answer at least internally consistent with what the login response
        // already claims.
        (sql => sql.Contains("fn_helpcollations", StringComparison.OrdinalIgnoreCase),
            Sync(BuildCollationLcidProbeResponse)),
        // "SELECT s.name AS [Name] FROM sys.schemas AS s WHERE (s.name=N'dbo')" — the "New Table"
        // designer checking the requested schema actually exists before letting the user pick it.
        // ASE has no schema concept at all (every table this proxy exposes is reported under "dbo"
        // by convention, see BuildDatabaseDefaultSchemaProbeResponse) — "dbo" exists (1 row), any
        // other requested name doesn't (0 rows), honest given what this proxy already claims.
        (sql => sql.Contains("sys.schemas AS s", StringComparison.OrdinalIgnoreCase),
            Sync(BuildSchemaExistsProbeResponse)),
        // "select sch.name, prn.type, user_name(sch.principal_id) from sys.schemas sch left outer
        // join sys.database_principals prn on prn.principal_id = sch.principal_id where
        // sch.principal_id <> 3 and sch.principal_id <> 4 order by sch.name" — the "New Table"
        // designer's schema PICKER (list every schema to choose from), a different query from the
        // single-schema existence check above — different alias ("sch", no "AS") so it didn't match
        // that probe's fingerprint (2026-10-27). This proxy only ever exposes "dbo" (see
        // BuildDatabaseDefaultSchemaProbeResponse) — one row is the honest, complete answer. No
        // aliases in the real query (bare "sch.name"/"prn.type"/function call), so the real column
        // names would be "name"/"type"/empty too.
        (sql => IsExactly(sql,
            "select sch.name , prn.type, user_name(sch.principal_id) from sys.schemas sch " +
            "left outer join sys.database_principals prn on prn.principal_id = sch.principal_id " +
            "where sch.principal_id <> 3 and sch.principal_id <> 4 order by sch.name"),
            Sync(BuildSchemaListProbeResponse)),
        // "SELECT name, convert(int, is_default), type FROM sys.filegroups" — the "New Table"
        // designer's filegroup picker (where to physically store the new table). ASE has no
        // filegroup concept (it has "segments", a different storage model) — every database this
        // proxy exposes behaves as if it only has the one filegroup every real SQL Server database
        // always has by default ("PRIMARY", is_default=1, type='FG' for a regular row filegroup).
        (sql => sql.Contains("sys.filegroups", StringComparison.OrdinalIgnoreCase),
            Sync(BuildFilegroupListProbeResponse)),
        // "New Table" designer's partition-function picker ("...from sys.partition_functions func
        // left outer join (sys.partition_parameters para join sys.types tp on ...) ..."). ASE has no
        // table-partitioning concept at all — zero rows is the honest, complete answer, not a
        // shortcut (2026-10-27).
        (sql => sql.Contains("sys.partition_functions", StringComparison.OrdinalIgnoreCase),
            Sync(BuildPartitionFunctionListProbeResponse)),
        // "New Table" designer's user-defined-type picker — a self-join on sys.types
        // ("a.system_type_id <> a.user_type_id ...") to find type ALIASES (CREATE TYPE ... FROM
        // ...), distinct from the base system types. This proxy has never created/exposed any user-
        // defined type, so zero rows is honest here too (2026-10-27) — not the same gap as the
        // table-list/column probes elsewhere in this file, which have real ASE data to report;
        // nothing analogous exists for this one.
        (sql => sql.Contains("a.system_type_id <> a.user_type_id", StringComparison.OrdinalIgnoreCase),
            Sync(BuildUserDefinedTypeListProbeResponse)),
        // Same "New Table" user-defined-type picker, a SECOND variant for CLR/assembly-backed types
        // ("from (sys.assembly_types a inner join sys.assembly_types b on a.is_user_defined = 1)
        // ..."). ASE has no CLR integration/assemblies at all — zero rows, honest (2026-10-27).
        (sql => sql.Contains("sys.assembly_types", StringComparison.OrdinalIgnoreCase),
            Sync(BuildAssemblyTypeListProbeResponse)),
        // "select o.name, schema_name(o.uid) from sysobjects o where OBJECTPROPERTY(o.id,
        // N'IsDefault') = 1 and o.name not like N'#%%' and o.category & 0x0800 = 0 and
        // OBJECTPROPERTY(o.id, N'IsMSShipped') = 0" — the "New Table" designer's standalone-DEFAULT-
        // object picker. Unlike most gaps in this file, this ISN'T an MSSQL-only catalog view — it's
        // real ASE sysobjects — but THIS ASE version's sysobjects has no "category" column at all
        // ("Invalid column name 'category'", 2026-10-27), so the real query can't run as-is either
        // way. Zero rows (no standalone DEFAULT objects to offer) is honest regardless of the
        // underlying reason.
        (sql => sql.Contains("OBJECTPROPERTY(o.id, N'IsDefault')", StringComparison.OrdinalIgnoreCase),
            Sync(BuildDefaultObjectListProbeResponse)),
        // "New Table" designer's per-table advanced-properties lookup (filegroup, text/image
        // filegroup, full-text catalog, change tracking, FileStream) for the specific table being
        // created — "... from sys.tables tbl left outer join sys.change_tracking_tables as ctt ...
        // where tbl.object_id = object_id(N'dbo.Table_1')". None of these MSSQL-only storage
        // features exist in ASE, and the table being designed doesn't exist yet anyway (still being
        // typed in, not yet CREATE TABLE'd) — zero rows is honest either way (2026-10-27).
        (sql => sql.Contains("sys.change_tracking_tables", StringComparison.OrdinalIgnoreCase),
            Sync(BuildTableAdvancedPropertiesProbeResponse)),
        // "SELECT (select schema_name()) AS [DefaultSchema]" — another "what's my current schema"
        // check, ASE has no schema_name() function. Same "dbo" answer as every other schema probe
        // in this file (BuildDatabaseDefaultSchemaProbeResponse, the sys.schemas check above).
        //
        // MUST use a column actually named "DefaultSchema", not BuildScalarResponse's generic blank
        // column name — found via "New Table" throwing "Column 'DefaultSchema' does not belong to
        // table Table." (2026-10-27): the real query aliases this column, so whatever reads the
        // result by name needs that exact name present, unlike the genuinely bare/unaliased scalars
        // (is_srvrolemember(...), suser_sname()) BuildScalarResponse was designed for.
        (sql => sql.Contains("schema_name()", StringComparison.OrdinalIgnoreCase),
            Sync(() => BuildNamedScalarResponse("DefaultSchema", "dbo"))),
        // AlwaysOn availability groups check ("EXECUTE @alwayson = master.dbo.xp_qv N'...',
        // @@SERVICENAME"). Unlike sys.databases, there's no real ASE equivalent to simulate against
        // — Sybase/ASE doesn't have an AlwaysOn-like feature at all — so this one is a pure fake,
        // not a shortcut taken instead of a real lookup. -1 matches what SQL Server itself reports
        // when the feature isn't applicable (ISNULL(@alwayson, -1) in the real script).
        (sql => sql.Contains("xp_qv", StringComparison.OrdinalIgnoreCase), Sync(() => BuildScalarResponse(-1))),
        // SQL Server Agent properties bootstrap — SMO's Server.JobServer getter needs this to
        // construct the "SQL Server Agent" tree node (see CLAUDE.md bug #37). Real shape: creates
        // a #tmp_sp_get_sqlagent_properties temp table, calls "exec msdb.dbo.sp_get_sqlagent_properties"
        // to populate it (one row), then a final 28-column SELECT off that temp table. ASE has no
        // SQL Server Agent at all — forwarding this to ASE fails at the exec step (no such proc in
        // msdb/master), the whole multi-statement batch aborts, and the client gets a TDS ERROR
        // instead of the one row Server.JobServer's constructor unconditionally expects — a
        // genuine, reproducible NullReferenceException deep in
        // Microsoft.SqlServer.Management.Smo.Agent.JobServer..ctor (confirmed via a full procdump
        // capture), not the generic one this proxy spent most of this session chasing. Reporting
        // "Agent service disabled" (ServiceStartMode=4, SqlAgentAutoStart=false) is the honest
        // answer — there's no real equivalent to fall back to here, same class as AlwaysOn/PBM.
        (sql => sql.Contains("sp_get_sqlagent_properties", StringComparison.OrdinalIgnoreCase),
            BuildSqlAgentPropertiesProbeResponse),
        // "does this server support Data-Tier Applications" check ("select case when
        // object_id('dbo.sysdac_instances') is not null then 1 else 0 end"). DACPAC/DAC is a pure
        // SQL Server/Azure feature with no ASE equivalent at all, and object_id() itself isn't a
        // function ASE understands the same way — forwarding this to ASE was the actual root cause
        // of the long-standing "silent hang on one of SSMS's ~8 parallel connections" (see CLAUDE.md
        // bug #32): the batch never got a probe match, fell through to the generic ASE execution
        // path, and ASE never returned (not even an error) for this specific query, leaving that
        // connection stuck forever. SMO apparently doesn't handle that stuck connection cleanly —
        // this is the most likely real cause of the non-deterministic client-side
        // NullReferenceException blocking Object Explorer. 0 (no DAC support) is the honest answer
        // either way.
        (sql => sql.Contains("sysdac_instances", StringComparison.OrdinalIgnoreCase),
            Sync(() => BuildScalarResponse(0))),
        // Object Explorer's "list tables in this database" query (sys.tables JOIN sys.indexes) —
        // found while debugging "no se ven las tablas en Object Explorer" (2026-10-26). This script
        // also calls serverproperty(N'Servername') once, lowercase, to build the [Urn] column — that
        // alone was enough to match the generic SERVERPROPERTY(...) fallback below (case-insensitive
        // Contains), which returned a single ServerName-shaped row instead of these real 11 columns.
        // Same silent "(0), no error" failure mode as bug #22/#39/#44. MUST be registered BEFORE the
        // generic fallback, same reasoning as every other combined-script probe above.
        (sql => HasExactAliases(sql,
                "Name", "Schema", "Urn", "CreateDate", "IsPartitioned", "HasSparseColumn",
                "HasNonClusteredIndex", "HasClusteredIndex", "HasPrimaryClusteredIndex", "HasXmlIndex", "HasXmlData"),
            BuildTableListProbeResponse),
        // SAME script family as above, but the "System Tables" node variant — different column set
        // (IsMemoryOptimized/IsNode/IsEdge instead of IsPartitioned/HasSparseColumn) and filters
        // "is_ms_shipped=1" instead of "=0". Found immediately after fixing the user-tables query
        // above: this one ALSO calls serverproperty(N'Servername') and, with no dedicated probe of
        // its own, fell into the same generic SERVERPROPERTY fallback — breaking Object Explorer's
        // Tables enumeration all over again even though the user-tables query right next to it now
        // worked fine. ASE has no "is_ms_shipped" concept at all (ch_runstatus, spt_values, mon*,
        // etc. are real ASE objects, not something this proxy can honestly call "Microsoft-shipped
        // system tables" in the MSSQL sense) — zero rows here is the honest answer, same reasoning
        // as the empty AlwaysOn/PBM probes above. Every real table this proxy knows about already
        // shows up once, under the plain Tables node (the probe above).
        (sql => HasExactAliases(sql,
                "Name", "Schema", "Urn", "CreateDate", "IsMemoryOptimized", "HasNonClusteredIndex",
                "HasClusteredIndex", "HasPrimaryClusteredIndex", "HasXmlIndex", "HasXmlData", "IsNode", "IsEdge"),
            Sync(BuildSystemTableListProbeResponse)),
        // Object Explorer's "columns of this one table" query — found right after fixing the table
        // list (2026-10-26): expanding a real table's Columns node hit the exact same
        // serverproperty(N'Servername')-in-the-Urn collision as every other per-table sub-node
        // query below. Unlike those, Columns has a real, direct ASE equivalent
        // (syscolumns/systypes) and is the one sub-node a user actually look at immediately after
        // a table shows up, so it gets real data instead of the generic empty fallback.
        (sql => HasExactAliases(sql,
                "Name", "Urn", "InPrimaryKey", "IsForeignKey", "DataType", "SystemType",
                "Length", "NumericPrecision", "NumericScale", "Nullable", "Computed"),
            BuildColumnListProbeResponse),
        // GENERALIZED probe for "give me real per-column field(s) of this table, straight off
        // sys.all_columns/clmns" — covers "SELECT clmns.name AS [Name] FROM sys.tables AS tbl
        // INNER JOIN sys.all_columns AS clmns ... WHERE (tbl.name=N'X' ...)" (the "Select Top N
        // Rows" column-name list that triggered a client-side "value passed in must be an enum
        // base" error when it fell into the empty catch-all, 2026-10-26, because SSMS generated
        // "SELECT TOP (100) FROM ..." with zero columns) AND any other, not-yet-seen query that
        // asks for a different plain "clmns.<field> AS [Alias]" combination the same way — instead
        // of writing one more dedicated probe (with its own exact alias set to keep in sync) every
        // time SMO sends a slightly different subset/order of these simple per-column fields.
        // Matches structurally: joins "sys.all_columns AS clmns" off "sys.tables AS tbl" filtered to
        // one table AND every single "AS [Alias]" in the query is a plain "clmns.<knownField>"
        // reference (see ColumnFieldRegex/KnownColumnFields below) — if even one selected column is
        // something ELSE (a join to systypes, a computed subquery, ...), this does NOT match, and
        // falls through to the dedicated Columns probe above (already registered first) or the
        // empty catch-all for anything neither of them recognizes — never fabricates a field it
        // doesn't actually have real data for.
        (sql => sql.Contains("sys.all_columns AS clmns", StringComparison.OrdinalIgnoreCase)
                && sql.Contains("sys.tables AS tbl", StringComparison.OrdinalIgnoreCase)
                && TablePropertyNameFilterRegex.IsMatch(sql)
                && IsAllPlainColumnFieldSelect(sql),
            BuildGenericColumnFieldProbeResponse),
        // Object Explorer's "Keys" node — the same per-table Index script as below, but filtered to
        // only the index(es) backing a primary key or unique constraint (WHERE "i.is_primary_key +
        // 2*i.is_unique_constraint=N'1'"). Fewer columns than the full Indexes list (no [IsUnique]),
        // so a distinct alias set — found right after adding a real PK to TestTabla (2026-10-26) to
        // see it show up here. Must be registered before the full Indexes probe below only for
        // readability (alias sets never collide, order doesn't matter for correctness between the
        // two) and before the generic empty catch-all (this one has real data to show).
        (sql => HasExactAliases(sql, "Name", "Urn", "IndexKeyType", "IndexType"),
            BuildKeyIndexListProbeResponse),
        // Object Explorer's "Indexes" node (unfiltered — every real index on the table, PK/unique or
        // not). Real ASE data via sysindexes + sp_pkeys (ASE's own ODBC-catalog proc, used instead
        // of guessing at undocumented status-bit layouts for "is this specifically the PK index").
        (sql => HasExactAliases(sql, "Name", "Urn", "IndexType", "IndexKeyType", "IsUnique"),
            BuildIndexListProbeResponse),
        // Generic catch-all for every OTHER "sub-node of one specific table" query (Keys/Indexes,
        // CheckConstraints, DefaultConstraints, EdgeConstraints, Triggers, Statistics, ForeignKeys,
        // ...) — all share the same structural shape as the Columns query above (joins off
        // "sys.tables AS tbl" filtered down to one "tbl.name=N'X'" + "SCHEMA_NAME(tbl.schema_id)")
        // and the same serverproperty(N'Servername')-in-the-Urn collision with the generic
        // SERVERPROPERTY fallback. None of these features (constraints, triggers, non-default
        // indexes, stats) are implemented by this proxy yet, and a newly created table genuinely
        // has none of them — zero rows, with the column set/types parsed generically from each
        // query's own "<expr> AS [Alias]" list, is the honest answer for all of them at once rather
        // than writing one near-identical dedicated probe per SMO sub-collection. MUST be registered
        // after the Columns probe above (more specific) and before the generic SERVERPROPERTY
        // fallback (same ordering reasoning as every other probe in this file).
        (sql => sql.Contains("sys.tables AS tbl", StringComparison.OrdinalIgnoreCase)
                && TablePropertyNameFilterRegex.IsMatch(sql)
                && sql.Contains("SCHEMA_NAME(tbl.schema_id)", StringComparison.OrdinalIgnoreCase),
            Sync(BuildEmptyTableSubCollectionProbeResponse)),
        // Generic fallback: ANY standalone SERVERPROPERTY('X') call not already matched above by a
        // more specific combined-script fingerprint. SMO queries individual properties piecemeal
        // in several places, not just via the one combined edition probe.
        (sql => sql.Contains("SERVERPROPERTY(", StringComparison.OrdinalIgnoreCase), BuildGenericServerPropertyResponse),
    };

    // Adapts a synchronous, sql-only (or parameterless) builder to the (sql, ase, ct) shape the
    // Probes table uses, without every probe having to care about async/ASE access it doesn't need.
    private static Func<string, AseConnection, CancellationToken, Task<byte[]>> Sync(Func<byte[]> build) =>
        (_, _, _) => Task.FromResult(build());

    private static Func<string, AseConnection, CancellationToken, Task<byte[]>> Sync(Func<string, byte[]> build) =>
        (sql, _, _) => Task.FromResult(build(sql));

    public static async Task<byte[]?> TryHandleAsync(string sql, AseConnection ase, CancellationToken ct)
    {
        foreach (var (matches, build) in Probes)
        {
            if (!matches(sql)) continue;
            return await build(sql, ase, ct);
        }

        return null;
    }

    // "edition" probe: SERVERPROPERTY('EDITION'/'EngineEdition'/'ProductVersion'),
    // @@MICROSOFTVERSION, sys.dm_os_host_info, CONNECTIONPROPERTY('net_transport').
    private static byte[] BuildEditionProbeResponse()
    {
        var writer = new TokenWriter();

        var infoColumns = new List<ProxyColumn>
        {
            new("DatabaseEngineType", ProxyColumnKind.Int32),
            new("DatabaseEngineEdition", ProxyColumnKind.Int32),
            new("ProductVersion", ProxyColumnKind.String),
            new("MicrosoftVersion", ProxyColumnKind.Int32),
        };
        writer.WriteColumnMetadata(infoColumns);
        writer.WriteRow(infoColumns, new object?[] { 1, 2, "8.00.194", 8 * 16777216 + 194 });
        writer.WriteDone(DoneStatus.More | DoneStatus.Count, 1);

        var hostColumns = new List<ProxyColumn> { new("host_platform", ProxyColumnKind.String) };
        writer.WriteColumnMetadata(hostColumns);
        writer.WriteRow(hostColumns, new object?[] { "Windows" });
        writer.WriteDone(DoneStatus.More | DoneStatus.Count, 1);

        var protocolColumns = new List<ProxyColumn> { new("ConnectionProtocol", ProxyColumnKind.String) };
        writer.WriteColumnMetadata(protocolColumns);
        writer.WriteRow(protocolColumns, new object?[] { "TCP" });
        writer.WriteDone(DoneStatus.Final | DoneStatus.Count, 1);

        return writer.ToArray();
    }

    // "is this a DAC/admin connection with SMO features enabled" probe (@@microsoftversion,
    // IS_SRVROLEMEMBER, sys.endpoints, sys.dm_exec_connections, sys.configurations).
    // AdminConnection=false (we're not a DAC connection) but SmoEnabled MUST be true — originally
    // this was false (configuration_id=16387, "SMO and DMO XPs", reported disabled), and SMO
    // actually RESPECTS that: it refuses to continue with "Accessing this server via SQL
    // Management Objects (SMO) or Distributed Management Objects (DMO) is currently not
    // permitted" — the real, literal SQL Server error for this exact config flag being off (see
    // CLAUDE.md bug #27). This only surfaced once the sysadmin bitmask (fix #26) stopped being
    // true, which apparently made SMO take this check seriously instead of skipping past it.
    private static byte[] BuildAdminConnectionProbeResponse()
    {
        var writer = new TokenWriter();
        var columns = new List<ProxyColumn>
        {
            new("AdminConnection", ProxyColumnKind.Boolean),
            new("SmoEnabled", ProxyColumnKind.Boolean),
        };
        writer.WriteColumnMetadata(columns);
        writer.WriteRow(columns, new object?[] { false, true });
        writer.WriteDone(DoneStatus.Final | DoneStatus.Count, 1);
        return writer.ToArray();
    }

    // Generic "bare scalar function call, no alias" response — same shape as the role-bitmask
    // probe (one unnamed column, one row, one value). Reused by SUSER_SNAME()/HAS_DBACCESS(...).
    private static byte[] BuildScalarResponse(object value)
    {
        var kind = value switch
        {
            bool => ProxyColumnKind.Boolean,
            int or long => ProxyColumnKind.Int32,
            _ => ProxyColumnKind.String,
        };
        var writer = new TokenWriter();
        var columns = new List<ProxyColumn> { new("", kind) };
        writer.WriteColumnMetadata(columns);
        writer.WriteRow(columns, new object?[] { value });
        writer.WriteDone(DoneStatus.Final | DoneStatus.Count, 1);
        return writer.ToArray();
    }

    // See the probe table entry above — two bare, unnamed int columns.
    private static byte[] BuildPermissionsProbeResponse()
    {
        var writer = new TokenWriter();
        var columns = new List<ProxyColumn> { new("", ProxyColumnKind.Int32), new("", ProxyColumnKind.Int32) };
        writer.WriteColumnMetadata(columns);
        writer.WriteRow(columns, new object?[] { -1, 1 });
        writer.WriteDone(DoneStatus.Final | DoneStatus.Count, 1);
        return writer.ToArray();
    }

    // Same shape as BuildScalarResponse but for a query that DOES alias its one column (unlike the
    // genuinely bare scalars BuildScalarResponse covers) — the client reads the result by that name,
    // so the column metadata has to actually carry it (CLAUDE.md: "Column 'X' does not belong to
    // table Table." when it doesn't).
    private static byte[] BuildNamedScalarResponse(string columnName, object value)
    {
        var kind = value switch
        {
            bool => ProxyColumnKind.Boolean,
            int or long => ProxyColumnKind.Int32,
            _ => ProxyColumnKind.String,
        };
        var writer = new TokenWriter();
        var columns = new List<ProxyColumn> { new(columnName, kind) };
        writer.WriteColumnMetadata(columns);
        writer.WriteRow(columns, new object?[] { value });
        writer.WriteDone(DoneStatus.Final | DoneStatus.Count, 1);
        return writer.ToArray();
    }

    private static readonly System.Text.RegularExpressions.Regex SchemaNameFilterRegex =
        new(@"s\.name\s*=\s*N?'([^']+)'", System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    // See probe table entry 4.5 above — unfiltered "every database, with extended columns" list.
    // ID uses the real ASE dbid (master..sysdatabases.dbid, same identity as db_id()) instead of a
    // made-up sequence number, since we already query that table for real names elsewhere.
    private static async Task<byte[]> BuildDatabaseListWithIdsProbeResponse(string sql, AseConnection ase, CancellationToken ct)
    {
        var columns = new List<ProxyColumn>
        {
            new("Name", ProxyColumnKind.String),
            new("ID", ProxyColumnKind.Int32),
            new("IsSystemObject", ProxyColumnKind.Boolean),
            new("Collation", ProxyColumnKind.String),
            new("IsAccessible", ProxyColumnKind.Boolean),
            new("DatabaseName2", ProxyColumnKind.String),
        };
        var writer = new TokenWriter();
        writer.WriteColumnMetadata(columns);

        var entries = await GetRealDatabaseIdsAsync(ase, ct);
        var collation = await GetRealCollationNameAsync(ase, ct);
        foreach (var (name, dbid) in entries)
        {
            writer.WriteRow(columns, new object?[]
            {
                name, dbid, SystemDatabaseNames.Contains(name, StringComparer.OrdinalIgnoreCase),
                collation, true, name,
            });
        }
        writer.WriteDone(DoneStatus.Final | DoneStatus.Count, (ulong)entries.Count);
        return writer.ToArray();
    }

    private static async Task<List<(string Name, int Dbid)>> GetRealDatabaseIdsAsync(AseConnection ase, CancellationToken ct)
    {
        var result = new List<(string, int)>();
        try
        {
            using var cmd = new AseCommand("SELECT name, dbid FROM master..sysdatabases ORDER BY name", ase);
            using var reader = (AseDataReader)await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
                result.Add((reader.GetString(0), Convert.ToInt32(reader.GetValue(1))));
        }
        catch
        {
            // fall through — empty list means this database picker shows empty rather than erroring
        }
        return result;
    }

    // See probe table entry above — ASE has no filegroup concept at all, so this is a pure fake
    // (not a shortcut over real data): every database this proxy exposes behaves as if it only has
    // the one filegroup every real SQL Server database always has ("PRIMARY").
    // See the probe table entry above — zero rows, columns matching the real query's order
    // (name, function_id, type, fanout, boundary_value_on_right, parameter_id, type_name,
    // max_length, precision, scale, collation_name — the last five come from an unaliased join onto
    // sys.partition_parameters/sys.types, which never executes since there are never any functions).
    private static byte[] BuildPartitionFunctionListProbeResponse()
    {
        var columns = new List<ProxyColumn>
        {
            new("name", ProxyColumnKind.String),
            new("function_id", ProxyColumnKind.Int32),
            new("type", ProxyColumnKind.String),
            new("fanout", ProxyColumnKind.Int32),
            new("boundary_value_on_right", ProxyColumnKind.Boolean),
            new("parameter_id", ProxyColumnKind.Int32),
            new("type_name", ProxyColumnKind.String),
            new("max_length", ProxyColumnKind.Int32),
            new("precision", ProxyColumnKind.Int32),
            new("scale", ProxyColumnKind.Int32),
            new("collation_name", ProxyColumnKind.String),
        };
        var writer = new TokenWriter();
        writer.WriteColumnMetadata(columns);
        writer.WriteDone(DoneStatus.Final | DoneStatus.Count, 0);
        return writer.ToArray();
    }

    // See the probe table entry above — zero rows, columns matching the real query's aliases in
    // order (user_type_name, user_type_schema, base_type_name, base_type_schema, max_length,
    // precision, scale, def_name, rule_name, is_nullable, def_schema, rule_schema, collation_name).
    private static byte[] BuildUserDefinedTypeListProbeResponse()
    {
        var columns = new List<ProxyColumn>
        {
            new("user_type_name", ProxyColumnKind.String),
            new("user_type_schema", ProxyColumnKind.String),
            new("base_type_name", ProxyColumnKind.String),
            new("base_type_schema", ProxyColumnKind.String),
            new("max_length", ProxyColumnKind.Int32),
            new("precision", ProxyColumnKind.Int32),
            new("scale", ProxyColumnKind.Int32),
            new("def_name", ProxyColumnKind.String),
            new("rule_name", ProxyColumnKind.String),
            new("is_nullable", ProxyColumnKind.Boolean),
            new("def_schema", ProxyColumnKind.String),
            new("rule_schema", ProxyColumnKind.String),
            new("collation_name", ProxyColumnKind.String),
        };
        var writer = new TokenWriter();
        writer.WriteColumnMetadata(columns);
        writer.WriteDone(DoneStatus.Final | DoneStatus.Count, 0);
        return writer.ToArray();
    }

    // See the probe table entry above — zero rows, columns matching the real query's aliases in
    // order (user_type_name, user_type_schema, max_length, precision, scale, def_name, rule_name,
    // is_nullable, def_schema, rule_schema, collation_name, assembly_id, assembly_class,
    // is_binary_ordered, is_fixed_length, user_type_id).
    private static byte[] BuildAssemblyTypeListProbeResponse()
    {
        var columns = new List<ProxyColumn>
        {
            new("user_type_name", ProxyColumnKind.String),
            new("user_type_schema", ProxyColumnKind.String),
            new("max_length", ProxyColumnKind.Int32),
            new("precision", ProxyColumnKind.Int32),
            new("scale", ProxyColumnKind.Int32),
            new("def_name", ProxyColumnKind.String),
            new("rule_name", ProxyColumnKind.String),
            new("is_nullable", ProxyColumnKind.Boolean),
            new("def_schema", ProxyColumnKind.String),
            new("rule_schema", ProxyColumnKind.String),
            new("collation_name", ProxyColumnKind.String),
            new("assembly_id", ProxyColumnKind.Int32),
            new("assembly_class", ProxyColumnKind.String),
            new("is_binary_ordered", ProxyColumnKind.Boolean),
            new("is_fixed_length", ProxyColumnKind.Boolean),
            new("user_type_id", ProxyColumnKind.Int32),
        };
        var writer = new TokenWriter();
        writer.WriteColumnMetadata(columns);
        writer.WriteDone(DoneStatus.Final | DoneStatus.Count, 0);
        return writer.ToArray();
    }

    // See the probe table entry above — zero rows, two bare/unaliased columns (o.name, schema_name(o.uid)).
    private static byte[] BuildDefaultObjectListProbeResponse()
    {
        var columns = new List<ProxyColumn> { new("name", ProxyColumnKind.String), new("", ProxyColumnKind.String) };
        var writer = new TokenWriter();
        writer.WriteColumnMetadata(columns);
        writer.WriteDone(DoneStatus.Final | DoneStatus.Count, 0);
        return writer.ToArray();
    }

    // See the probe table entry above — zero rows, columns matching the real query's order (bare
    // "tbl.X" references get their column name from the identifier itself, like real SQL Server;
    // only the expressions without AS end up unnamed).
    private static byte[] BuildTableAdvancedPropertiesProbeResponse()
    {
        var columns = new List<ProxyColumn>
        {
            new("TableFg", ProxyColumnKind.String),
            new("TexImageFg", ProxyColumnKind.String),
            new("FulltextCatalog", ProxyColumnKind.String),
            new("TextInrowLimit", ProxyColumnKind.Int32),
            new("", ProxyColumnKind.Int32),
            new("DirectOwner", ProxyColumnKind.String),
            new("is_replicated", ProxyColumnKind.Boolean),
            new("lock_escalation_desc", ProxyColumnKind.String),
            new("", ProxyColumnKind.Boolean),
            new("", ProxyColumnKind.Boolean),
            new("FileStreamFileGroup", ProxyColumnKind.String),
            new("FileStreamPartitionScheme", ProxyColumnKind.String),
        };
        var writer = new TokenWriter();
        writer.WriteColumnMetadata(columns);
        writer.WriteDone(DoneStatus.Final | DoneStatus.Count, 0);
        return writer.ToArray();
    }

    private static byte[] BuildFilegroupListProbeResponse()
    {
        var columns = new List<ProxyColumn>
        {
            new("name", ProxyColumnKind.String),
            new("is_default", ProxyColumnKind.Int32),
            new("type", ProxyColumnKind.String),
        };
        var writer = new TokenWriter();
        writer.WriteColumnMetadata(columns);
        writer.WriteRow(columns, new object?[] { "PRIMARY", 1, "FG" });
        writer.WriteDone(DoneStatus.Final | DoneStatus.Count, 1);
        return writer.ToArray();
    }

    // See the probe table entry above — the one schema this proxy exposes ("dbo"), with a plausible
    // principal type ('S' = SQL_USER, the real sys.database_principals.type for a standard login-
    // backed schema owner) and owner name.
    private static byte[] BuildSchemaListProbeResponse()
    {
        var columns = new List<ProxyColumn>
        {
            new("name", ProxyColumnKind.String),
            new("type", ProxyColumnKind.String),
            new("", ProxyColumnKind.String),
        };
        var writer = new TokenWriter();
        writer.WriteColumnMetadata(columns);
        writer.WriteRow(columns, new object?[] { "dbo", "S", "dbo" });
        writer.WriteDone(DoneStatus.Final | DoneStatus.Count, 1);
        return writer.ToArray();
    }

    private static byte[] BuildSchemaExistsProbeResponse(string sql)
    {
        var match = SchemaNameFilterRegex.Match(sql);
        var exists = match.Success && string.Equals(match.Groups[1].Value, "dbo", StringComparison.OrdinalIgnoreCase);
        var columns = new List<ProxyColumn> { new("Name", ProxyColumnKind.String) };
        var writer = new TokenWriter();
        writer.WriteColumnMetadata(columns);
        var rowCount = 0UL;
        if (exists)
        {
            writer.WriteRow(columns, new object?[] { "dbo" });
            rowCount = 1;
        }
        writer.WriteDone(DoneStatus.Final | DoneStatus.Count, rowCount);
        return writer.ToArray();
    }

    private static byte[] BuildCollationLcidProbeResponse()
    {
        var writer = new TokenWriter();
        var columns = new List<ProxyColumn> { new("LocaleID", ProxyColumnKind.Int32) };
        writer.WriteColumnMetadata(columns);
        writer.WriteRow(columns, new object?[] { 1033 });
        writer.WriteDone(DoneStatus.Final | DoneStatus.Count, 1);
        return writer.ToArray();
    }

    private static readonly string[] SystemDatabaseNames = { "master", "model", "msdb", "tempdb" };

    // See the probe table entry above — THE query that actually populates "Databases" with user
    // database nodes. Real ASE names, filtered the same way the real query's WHERE clause does
    // (exclude master/model/msdb/tempdb — those show under "System Databases" instead). Everything
    // else in the row (collation/compat-level/recovery-model/...) is fabricated, consistent with
    // what the rest of this proxy already claims (SQL_Latin1_General_CP1_CI_AS collation, SQL
    // Server 2000 compat level 80 matching the claimed VersionMajor=8).
    private static async Task<byte[]> BuildUserDatabaseListProbeResponse(string sql, AseConnection ase, CancellationToken ct)
    {
        var allNames = await GetRealDatabaseNamesAsync(ase, ct);
        var names = allNames.Where(n => !SystemDatabaseNames.Contains(n, StringComparer.OrdinalIgnoreCase)).ToList();

        // Single-database refresh variant ("WHERE (dtb.name=N'Banksys')" instead of
        // "WHERE (dtb.name in (...))") — narrow down to just that one if present.
        var filterMatch = DbPropertyNameFilterRegex.Match(sql);
        if (filterMatch.Success)
            names = names.Where(n => string.Equals(n, filterMatch.Groups[1].Value, StringComparison.OrdinalIgnoreCase)).ToList();

        var columns = new List<ProxyColumn>
        {
            new("Database_Name", ProxyColumnKind.String),
            new("Database_Urn", ProxyColumnKind.String),
            new("Database_ContainmentType", ProxyColumnKind.Int32),
            new("Database_RecoveryModel", ProxyColumnKind.Int32),
            new("Database_Owner", ProxyColumnKind.String),
            new("Database_Status", ProxyColumnKind.Int32),
            new("Database_CompatibilityLevel", ProxyColumnKind.Int32),
            new("Database_IsSqlDw", ProxyColumnKind.Boolean),
            new("RecoveryModel", ProxyColumnKind.Int32),
            new("UserAccess", ProxyColumnKind.Int32),
            new("ReadOnly", ProxyColumnKind.Boolean),
            new("Database_DatabaseName2", ProxyColumnKind.String),
        };

        var flags = await GetRealDatabaseFlagsAsync(ase, ct);

        var writer = new TokenWriter();
        writer.WriteColumnMetadata(columns);
        foreach (var name in names)
        {
            var (readOnly, singleUser) = flags.TryGetValue(name, out var f) ? f : (false, false);
            writer.WriteRow(columns, new object?[]
            {
                name, $"Server[@Name='SQLPROXY']/Database[@Name='{name}']",
                0, 1,
                "sa", 1,
                80, false,
                1, singleUser ? 1 : 0,
                readOnly, name,
            });
        }
        writer.WriteDone(DoneStatus.Final | DoneStatus.Count, (ulong)names.Count);
        return writer.ToArray();
    }

    // Real ASE sysdatabases.status/status2 bits for ReadOnly/UserAccess instead of always claiming
    // false/0 — per-database, so fetched once per call and looked up by name. Bit values below are
    // Sybase ASE's documented ones (status & 0x1000 = "dbo use only"/single-user, status2 & 0x10 =
    // "read only"); falls back to an empty map (same as the old hardcoded false/0 everywhere) if the
    // query fails for any reason, same defensive pattern as GetRealDatabaseNamesAsync.
    private static async Task<Dictionary<string, (bool ReadOnly, bool SingleUser)>> GetRealDatabaseFlagsAsync(AseConnection ase, CancellationToken ct)
    {
        var result = new Dictionary<string, (bool, bool)>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var cmd = new AseCommand("SELECT name, status, status2 FROM master..sysdatabases", ase);
            using var reader = (AseDataReader)await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                var name = reader.GetString(0);
                var status = Convert.ToInt64(reader.GetValue(1));
                var status2 = Convert.ToInt64(reader.GetValue(2));
                result[name] = ((status2 & 0x10) != 0, (status & 0x1000) != 0);
            }
        }
        catch
        {
            // fall through — empty map means every lookup below defaults to (false, false)
        }
        return result;
    }

    // Object Explorer's "list the databases on this server" query — e.g.
    // "SELECT dtb.name AS [Name], dtb.state AS [State] FROM master.sys.databases dtb". Unlike most
    // probes here, ASE DOES have a real, direct equivalent of sys.databases: master..sysdatabases.
    // So instead of fabricating a single "master" row, actually query it and list the real
    // databases that exist on the ASE instance — "State" is hardcoded to 0 (ONLINE) for all of
    // them since mapping Sybase's sysdatabases.status bitmask to MSSQL's state enum isn't done
    // here (known simplification — fine for a dev ASE instance where nothing is actually offline).
    // Falls back to a single fake "master" row if the real query fails for any reason (e.g. this
    // session's AseConnection isn't in a state that can run it) rather than surfacing an error.
    private static async Task<byte[]> BuildDatabaseListProbeResponse(string sql, AseConnection ase, CancellationToken ct)
    {
        var names = await GetRealDatabaseNamesAsync(ase, ct);
        var columns = new List<ProxyColumn>
        {
            new("Name", ProxyColumnKind.String),
            new("State", ProxyColumnKind.Byte), // real sys.databases.state is tinyint — see CLAUDE.md bug #22
        };

        var writer = new TokenWriter();
        writer.WriteColumnMetadata(columns);
        foreach (var name in names)
            writer.WriteRow(columns, new object?[] { name, (byte)0 });
        writer.WriteDone(DoneStatus.Final | DoneStatus.Count, (ulong)names.Count);
        return writer.ToArray();
    }

    // 28-column shape exact-matched from the real script (see probe table entry above). Most
    // columns are NULL/empty because the real source (#tmp_sp_get_sqlagent_properties) would be
    // empty too if Agent genuinely weren't configured — SysAdminOnly is CAST(1 AS bit), a literal
    // in the real query unconditionally, not data-dependent, so it stays true regardless.
    //
    // ServiceStartMode/SqlAgentAutoStart: real ASE has its own Job Scheduler component (installed
    // alongside this project's ASE instance — see root CLAUDE.md), checked via its real
    // "enable job scheduler" sp_configure flag instead of unconditionally claiming "Agent
    // disabled". Falls back to the old disabled defaults if the query fails for any reason.
    private static async Task<byte[]> BuildSqlAgentPropertiesProbeResponse(string sql, AseConnection ase, CancellationToken ct)
    {
        var jobSchedulerEnabled = await IsRealJobSchedulerEnabledAsync(ase, ct);
        var writer = new TokenWriter();
        var columns = new List<ProxyColumn>
        {
            new("Name", ProxyColumnKind.String), new("MsxServerName", ProxyColumnKind.String),
            new("JobServerType", ProxyColumnKind.Int32), new("SqlServerRestart", ProxyColumnKind.Boolean),
            new("SqlAgentRestart", ProxyColumnKind.Boolean), new("MaximumHistoryRows", ProxyColumnKind.Int32),
            new("MaximumJobHistoryRows", ProxyColumnKind.Int32), new("ErrorLogFile", ProxyColumnKind.String),
            new("AgentLogLevel", ProxyColumnKind.Int32), new("NetSendRecipient", ProxyColumnKind.String),
            new("AgentShutdownWaitTime", ProxyColumnKind.Int32), new("SqlAgentMailProfile", ProxyColumnKind.String),
            new("SaveInSentFolder", ProxyColumnKind.Boolean), new("WriteOemErrorLog", ProxyColumnKind.Boolean),
            new("IsCpuPollingEnabled", ProxyColumnKind.Boolean), new("IdleCpuPercentage", ProxyColumnKind.Int32),
            new("IdleCpuDuration", ProxyColumnKind.Int32), new("LoginTimeout", ProxyColumnKind.Int32),
            new("HostLoginName", ProxyColumnKind.String), new("LocalHostAlias", ProxyColumnKind.String),
            new("SqlAgentAutoStart", ProxyColumnKind.Boolean), new("ReplaceAlertTokensEnabled", ProxyColumnKind.Boolean),
            new("DatabaseMailProfile", ProxyColumnKind.String), new("AgentMailType", ProxyColumnKind.Int32),
            new("SysAdminOnly", ProxyColumnKind.Boolean), new("ServiceStartMode", ProxyColumnKind.Int32),
            new("ServiceAccount", ProxyColumnKind.String), new("AgentDomainGroup", ProxyColumnKind.String),
        };
        writer.WriteColumnMetadata(columns);
        writer.WriteRow(columns, new object?[]
        {
            "SQLPROXY", "",
            null, null,
            null, null,
            null, null,
            null, "",
            null, "",
            null, null,
            null, null,
            null, null,
            "", "",
            jobSchedulerEnabled, null,
            "", 0,
            // ServiceStartMode: SC_START_TYPE convention used elsewhere in this project —
            // 2=Automatic, 4=Disabled.
            true, jobSchedulerEnabled ? 2 : 4,
            "", "",
        });
        writer.WriteDone(DoneStatus.Final | DoneStatus.Count, 1);
        return writer.ToArray();
    }

    private static async Task<bool> IsRealJobSchedulerEnabledAsync(AseConnection ase, CancellationToken ct)
    {
        try
        {
            using var cmd = new AseCommand("sp_configure 'enable job scheduler'", ase);
            using var reader = (AseDataReader)await cmd.ExecuteReaderAsync(ct);
            if (!await reader.ReadAsync(ct)) return false;
            // sp_configure's result has more columns than just (Parameter Name, Default, Memory
            // Used, Config Value, Run Value) — this ASE version's last column turned out to be a
            // "dynamic"/"static" type descriptor, not the Run Value, breaking an earlier
            // by-position assumption. Find "Run Value" by name instead of guessing a fixed ordinal.
            var runValueIndex = Enumerable.Range(0, reader.FieldCount)
                .FirstOrDefault(i => reader.GetName(i).Equals("Run Value", StringComparison.OrdinalIgnoreCase), -1);
            if (runValueIndex < 0) return false;
            return Convert.ToInt64(reader.GetValue(runValueIndex)) != 0;
        }
        catch
        {
            return false; // fall back to the old "Agent disabled" default
        }
    }

    // See the probe table entry above — "SELECT CAST(has_dbaccess(dtb.name) AS bit) AS
    // [IsAccessible] FROM master.sys.databases AS dtb WHERE (dtb.name=N'X')". Real ASE data: we're
    // always "sa", so any database that actually exists is accessible.
    private static async Task<byte[]> BuildDatabaseIsAccessibleProbeResponse(string sql, AseConnection ase, CancellationToken ct)
    {
        var filterMatch = DbPropertyNameFilterRegex.Match(sql);
        var accessible = false;
        if (filterMatch.Success)
        {
            var names = await GetRealDatabaseNamesAsync(ase, ct);
            accessible = names.Any(n => string.Equals(n, filterMatch.Groups[1].Value, StringComparison.OrdinalIgnoreCase));
        }
        return BuildScalarResponse(accessible);
    }

    // See the probe table entry above — "SELECT '' AS [DefaultSchema], dtb.name AS [DatabaseName]
    // FROM master.sys.databases AS dtb WHERE (dtb.name=N'X')".
    private static async Task<byte[]> BuildDatabaseDefaultSchemaProbeResponse(string sql, AseConnection ase, CancellationToken ct)
    {
        var columns = new List<ProxyColumn> { new("DefaultSchema", ProxyColumnKind.String), new("DatabaseName", ProxyColumnKind.String) };
        var writer = new TokenWriter();
        writer.WriteColumnMetadata(columns);

        var filterMatch = DbPropertyNameFilterRegex.Match(sql);
        var rowCount = 0UL;
        if (filterMatch.Success)
        {
            var names = await GetRealDatabaseNamesAsync(ase, ct);
            var match = names.FirstOrDefault(n => string.Equals(n, filterMatch.Groups[1].Value, StringComparison.OrdinalIgnoreCase));
            if (match is not null)
            {
                writer.WriteRow(columns, new object?[] { "dbo", match });
                rowCount = 1;
            }
        }

        writer.WriteDone(DoneStatus.Final | DoneStatus.Count, rowCount);
        return writer.ToArray();
    }

    private static readonly System.Text.RegularExpressions.Regex DbPropertyColumnRegex =
        new(@"dtb\.(\w+)\s+AS\s+\[(\w+)\]", System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    private static readonly System.Text.RegularExpressions.Regex DbPropertyNameFilterRegex =
        new(@"dtb\.name\s*=\s*N?'([^']*)'", System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    // See the probe table entry above — per-database property lookup, real shape captured via the
    // mssql-passthrough comparison log. "name"/"catalog_collation_type" come straight from the
    // real ASE database list; "collation_name" is fabricated (same fixed collation this proxy
    // already claims everywhere else — ASE's real collation isn't MSSQL-shaped at all).
    private static async Task<byte[]> BuildDatabasePropertyLookupResponse(string sql, AseConnection ase, CancellationToken ct)
    {
        var columns = new List<(string SourceColumn, string Alias)>();
        foreach (System.Text.RegularExpressions.Match m in DbPropertyColumnRegex.Matches(sql))
            columns.Add((m.Groups[1].Value, m.Groups[2].Value));

        var filterMatch = DbPropertyNameFilterRegex.Match(sql);
        var requestedName = filterMatch.Success ? filterMatch.Groups[1].Value : null;

        var proxyColumns = columns
            .Select(c => new ProxyColumn(c.Alias, c.SourceColumn.Equals("catalog_collation_type", StringComparison.OrdinalIgnoreCase)
                ? ProxyColumnKind.Int32
                : ProxyColumnKind.String))
            .ToList();

        var writer = new TokenWriter();
        writer.WriteColumnMetadata(proxyColumns);

        var realNames = requestedName is null ? new List<string>() : await GetRealDatabaseNamesAsync(ase, ct);
        var match = realNames.FirstOrDefault(n => string.Equals(n, requestedName, StringComparison.OrdinalIgnoreCase));

        var rowCount = 0UL;
        if (match is not null)
        {
            var collation = await GetRealCollationNameAsync(ase, ct);
            // SourceColumn is always "name" here regardless of which alias ([Name] or
            // [DatabaseName2]) the query used for it — both shapes select dtb.name verbatim.
            var values = columns.Select(c => c.SourceColumn.ToLowerInvariant() switch
            {
                "name" => (object?)match,
                "collation_name" => collation,
                "catalog_collation_type" => 0,
                _ => null,
            }).ToArray();
            writer.WriteRow(proxyColumns, values);
            rowCount = 1;
        }

        writer.WriteDone(DoneStatus.Final | DoneStatus.Count, rowCount);
        return writer.ToArray();
    }

    private static readonly System.Text.RegularExpressions.Regex HasDbAccessNameRegex =
        new(@"has_dbaccess\s*\(\s*'([^']+)'\s*\)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    private static async Task<byte[]> BuildHasDbAccessProbeResponse(string sql, AseConnection ase, CancellationToken ct)
    {
        var match = HasDbAccessNameRegex.Match(sql);
        var accessible = false;
        if (match.Success)
        {
            var requested = match.Groups[1].Value;
            // "msdb" will never show up in ASE's real database list (there's no such concept in
            // Sybase) — but ClientSession.MapToRealAseDatabase already redirects a login scoped to
            // "msdb" to master transparently, so it genuinely IS usable. Answering false here (the
            // literal truth about ASE's database list) contradicted that architectural decision and
            // was, in practice, WHY SMO showed "Cannot display policy health state... Permission to
            // access the msdb database is required" on every connect — it checks HAS_DBACCESS('msdb')
            // first and never even attempts the real policy query once that comes back false (see
            // CLAUDE.md bug #28). Match MapToRealAseDatabase's redirect decision here instead of the
            // raw real list, so the two stay consistent.
            accessible = string.Equals(requested, "msdb", StringComparison.OrdinalIgnoreCase);
            if (!accessible)
            {
                var names = await GetRealDatabaseNamesAsync(ase, ct);
                accessible = names.Any(n => string.Equals(n, requested, StringComparison.OrdinalIgnoreCase));
            }
        }
        return BuildScalarResponse(accessible);
    }

    // "SELECT CASE WHEN has_dbaccess(N'Banksys') = 1 THEN 'true' ELSE 'false' END" — the "New Table"
    // designer's accessibility check, wants the literal string 'true'/'false' rather than a bit.
    // Same real-data policy as BuildHasDbAccessProbeResponse above (checks the real ASE database
    // list, msdb redirected to "accessible" consistent with MapToRealAseDatabase) — just a
    // different response shape for a differently-worded version of the same question.
    private static readonly System.Text.RegularExpressions.Regex HasDbAccessCaseRegex =
        new(@"CASE\s+WHEN\s+has_dbaccess\s*\(\s*N?'([^']+)'\s*\)\s*=\s*1\s+THEN\s+'true'\s+ELSE\s+'false'\s+END",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    private static async Task<byte[]> BuildDatabaseIsAccessibleCaseProbeResponse(string sql, AseConnection ase, CancellationToken ct)
    {
        var match = HasDbAccessCaseRegex.Match(sql);
        var accessible = false;
        if (match.Success)
        {
            var requested = match.Groups[1].Value;
            accessible = string.Equals(requested, "msdb", StringComparison.OrdinalIgnoreCase);
            if (!accessible)
            {
                var names = await GetRealDatabaseNamesAsync(ase, ct);
                accessible = names.Any(n => string.Equals(n, requested, StringComparison.OrdinalIgnoreCase));
            }
        }
        return BuildScalarResponse(accessible ? "true" : "false");
    }

    // "SELECT dtb.name AS [Database] FROM master.dbo.sysdatabases dtb WHERE (has_dbaccess(dtb.name)
    // = 1)" — same real data as above, different single-column shape. We always log into ASE as
    // "sa", which can see every database, so "all of them" is the honest answer to "which ones can
    // this login access".
    private static async Task<byte[]> BuildAccessibleDatabaseListProbeResponse(string sql, AseConnection ase, CancellationToken ct)
    {
        var names = await GetRealDatabaseNamesAsync(ase, ct);
        var columns = new List<ProxyColumn> { new("Database", ProxyColumnKind.String) };

        var writer = new TokenWriter();
        writer.WriteColumnMetadata(columns);
        foreach (var name in names)
            writer.WriteRow(columns, new object?[] { name });
        writer.WriteDone(DoneStatus.Final | DoneStatus.Count, (ulong)names.Count);
        return writer.ToArray();
    }

    // Shared by both database-list probes — the real database names on the ASE instance this
    // session is connected to, via master..sysdatabases (ASE's direct equivalent of MSSQL's
    // sys.databases). Falls back to a single fake "master" entry if the real query fails OR takes
    // too long, rather than surfacing an error or hanging the whole session indefinitely.
    //
    // The timeout here is a Task.WhenAny race, not a CancellationToken handed to the ASE call —
    // deliberately. A real hang was observed (CLAUDE.md bug #31: one SSMS connection sent a batch
    // that matched this probe and then NEVER completed — no exception, no log line, nothing,
    // consistent with the "Object reference not set" dialog that kept appearing non-deterministically
    // across many connect attempts). It's unverified whether AdoNetCore.AseClient actually honors
    // cancellation on a genuinely stuck network read — if it doesn't, passing a token into
    // ExecuteReaderAsync wouldn't unblock anything. Racing with Task.Delay guarantees THIS method
    // returns within the timeout regardless, even if the underlying ASE call keeps running
    // unobserved in the background.
    private static async Task<List<string>> GetRealDatabaseNamesAsync(AseConnection ase, CancellationToken ct)
    {
        try
        {
            var queryTask = QueryRealDatabaseNamesAsync(ase, ct);
            var timeoutTask = Task.Delay(TimeSpan.FromSeconds(5), ct);
            if (await Task.WhenAny(queryTask, timeoutTask) == queryTask)
                return await queryTask;
        }
        catch
        {
            // fall through to the fallback below
        }

        var names = new List<string> { "master" };
        return names;
    }

    private static async Task<List<string>> QueryRealDatabaseNamesAsync(AseConnection ase, CancellationToken ct)
    {
        var names = new List<string>();
        using var cmd = new AseCommand("SELECT name FROM master..sysdatabases ORDER BY name", ase);
        using var reader = (AseDataReader)await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            names.Add(reader.GetString(0));
        return names;
    }

    // ASE's actual configured default character set — "cp850", per this project's own install
    // notes (root CLAUDE.md: "sqlsrv.default_characterset=cp850" in the real setup response file
    // used when this ASE instance was installed). Real, verified data about this specific
    // instance, just sourced from the project's own records instead of a live query — a live
    // "SELECT @@character_set" was tried first and genuinely doesn't exist as an ASE global
    // variable (confirmed: ASE's own "Must declare variable '@@character_set'" error, not a driver
    // quirk), and guessing at the real catalog query (syscharsets/sysconfigures) risked claiming
    // something wrong, which is worse than this known-correct fact. Simpler and safer than
    // claiming MSSQL's "SQL_Latin1_General_CP1_CI_AS" everywhere, per the project's real-data
    // policy — still fabricated in the sense that it's not live-queried, but it's the real,
    // documented truth about this ASE instance rather than an invented MSSQL-flavored value.
    private const string RealAseCollationName = "cp850";

    private static Task<string> GetRealCollationNameAsync(AseConnection ase, CancellationToken ct) =>
        Task.FromResult(RealAseCollationName);

    // Server-role-membership bitmask probe (SSMS checks which menu items/permissions to show):
    // "select is_srvrolemember('sysadmin') * 1 + is_srvrolemember('serveradmin') * 2 + ...". No
    // alias, so the real column name would be empty too.
    //
    // History: reported sysadmin=1 (honest — "sa" really is sysadmin on ASE) → hit "Specified cast
    // is not valid"; switched to 0 to dodge SMO's admin-only feature cascade → connection got
    // further but still eventually hit the same class of NullReferenceException/InvalidCastException
    // a few probes later, suggesting the "not admin" path has its OWN SMO bugs, not just fewer of
    // them. Currently back to 1 (honest answer) now that SmoEnabled is ALSO true (fix #27) — that
    // combination (sysadmin=1 + SmoEnabled=false) was never actually tested before reporting this
    // as "the" fix; worth re-testing against SmoEnabled=true before concluding either value is
    // right. If this regresses, see CLAUDE.md bug #26/#29 for the full back-and-forth.
    private static async Task<byte[]> BuildServerRoleBitmaskProbeResponse(string sql, AseConnection ase, CancellationToken ct)
    {
        // Real ASE catalog check instead of blindly assuming "sa" always carries sa_role — the sa
        // login almost certainly does (it's the Sybase built-in admin role), but confirming against
        // the real catalog is more honest than hardcoding it, per the project's real-data policy.
        // Only bit 1 (sysadmin) has a real ASE equivalent to check this way; the other 7 roles in
        // this bitmask (serveradmin, setupadmin, ...) are MSSQL-specific granular roles ASE doesn't
        // have a matching concept for, so they stay 0 regardless.
        var isSysAdmin = await HasRealSysAdminRoleAsync(ase, ct);
        var writer = new TokenWriter();
        var columns = new List<ProxyColumn> { new("", ProxyColumnKind.Int32) };
        writer.WriteColumnMetadata(columns);
        writer.WriteRow(columns, new object?[] { isSysAdmin ? 1 : 0 });
        writer.WriteDone(DoneStatus.Final | DoneStatus.Count, 1);
        return writer.ToArray();
    }

    private static async Task<bool> HasRealSysAdminRoleAsync(AseConnection ase, CancellationToken ct)
    {
        try
        {
            using var cmd = new AseCommand(
                "SELECT 1 FROM master..sysloginroles slr, master..syssrvroles ssr " +
                "WHERE slr.srid = ssr.srid AND ssr.name = 'sa_role' AND slr.suid = suser_id()",
                ase);
            using var reader = (AseDataReader)await cmd.ExecuteReaderAsync(ct);
            return await reader.ReadAsync(ct);
        }
        catch
        {
            return true; // fall back to the long-proven-working honest default
        }
    }

    // "PolicyStore[@Name=...]" lookup — exact shape captured from a real SQL Server, see the probe
    // table entry above. Enabled=false so SMO treats Policy-Based Management as not configured.
    private static byte[] BuildPolicyStoreProbeResponse()
    {
        var writer = new TokenWriter();
        var columns = new List<ProxyColumn>
        {
            new("Urn", ProxyColumnKind.String),
            new("Name", ProxyColumnKind.String),
            new("Enabled", ProxyColumnKind.Boolean),
            new("HistoryRetentionInDays", ProxyColumnKind.Int32),
            new("LogOnSuccess", ProxyColumnKind.Boolean),
        };
        writer.WriteColumnMetadata(columns);
        writer.WriteRow(columns, new object?[] { "PolicyStore[@Name='SQLPROXY']", "SQLPROXY", false, 0, false });
        writer.WriteDone(DoneStatus.Final | DoneStatus.Count, 1);
        return writer.ToArray();
    }

    // Exact shape of the "server root properties" bootstrap script's final SELECT — 27 columns, in
    // order. ResourceLastUpdateDateTime is left NULL rather than a fake string: a real DateTime
    // column holding a string value is exactly the kind of type mismatch that broke SMO before
    // (see CLAUDE.md bug #8) — NULL is safe for any declared type, a wrong-but-non-null value isn't.
    // The ~59-column server bootstrap script — see the probe table entry above. Most of these
    // columns come from xp_instance_regread OUTPUT params that would be NULL against any real
    // server without that exact registry layout anyway (this proxy has no registry to read from at
    // all) — NULL/the same ISNULL(...) fallback the real script itself falls back to is the honest
    // answer for those, not a shortcut. ClusterQuorumType=4/ClusterQuorumState=3 in particular are
    // literally the script's OWN hardcoded ISNULL defaults (ISNULL(@quorum_type, 4)), so a real
    // non-clustered SQL Server reports the exact same values here, not something ASE-specific.
    // ResourceLastUpdateDateTime uses the real ProxyColumnKind.DateTime (NULL — same reasoning as
    // the 27-column probe: a genuine DateTime column holding a string would risk the bug #22 class
    // of silent client-side swallow). Other values reuse the same constants this proxy already
    // claims elsewhere (collation, CollationID/ComparisonStyle/SqlCharSet/SqlSortOrder, RootDirectory,
    // version strings) so nothing here contradicts what another probe already answered.
    private static async Task<byte[]> BuildFullServerBootstrapProbeResponse(string sql, AseConnection ase, CancellationToken ct)
    {
        var collation = await GetRealCollationNameAsync(ase, ct);
        var writer = new TokenWriter();
        var columns = new List<ProxyColumn>
        {
            new("AuditLevel", ProxyColumnKind.Int32),
            new("NumberOfLogFiles", ProxyColumnKind.Int32),
            new("LoginMode", ProxyColumnKind.Int32),
            new("MailProfile", ProxyColumnKind.String),
            new("BackupDirectory", ProxyColumnKind.String),
            new("PerfMonMode", ProxyColumnKind.Int32),
            new("InstallDataDirectory", ProxyColumnKind.String),
            new("ServiceName", ProxyColumnKind.String),
            new("ErrorLogPath", ProxyColumnKind.String),
            new("RootDirectory", ProxyColumnKind.String),
            new("IsCaseSensitive", ProxyColumnKind.Boolean),
            new("MaxPrecision", ProxyColumnKind.Int32),
            new("IsFullTextInstalled", ProxyColumnKind.Boolean),
            new("VersionString", ProxyColumnKind.String),
            new("Edition", ProxyColumnKind.String),
            new("ProductLevel", ProxyColumnKind.String),
            new("ProductUpdateLevel", ProxyColumnKind.String),
            new("IsSingleUser", ProxyColumnKind.Boolean),
            new("EngineEdition", ProxyColumnKind.Int32),
            new("Collation", ProxyColumnKind.String),
            new("IsClustered", ProxyColumnKind.Boolean),
            new("NetName", ProxyColumnKind.String),
            new("ComputerNamePhysicalNetBIOS", ProxyColumnKind.String),
            new("ServiceStartMode", ProxyColumnKind.Int32),
            new("MasterDBLogPath", ProxyColumnKind.String),
            new("MasterDBPath", ProxyColumnKind.String),
            new("DefaultFile", ProxyColumnKind.String),
            new("DefaultLog", ProxyColumnKind.String),
            new("ResourceVersionString", ProxyColumnKind.String),
            new("ResourceLastUpdateDateTime", ProxyColumnKind.DateTime),
            new("CollationID", ProxyColumnKind.Int32),
            new("ComparisonStyle", ProxyColumnKind.Int32),
            new("SqlCharSet", ProxyColumnKind.Byte),
            new("SqlCharSetName", ProxyColumnKind.String),
            new("SqlSortOrder", ProxyColumnKind.Byte),
            new("SqlSortOrderName", ProxyColumnKind.String),
            new("BuildClrVersionString", ProxyColumnKind.String),
            new("ServiceAccount", ProxyColumnKind.String),
            new("NamedPipesEnabled", ProxyColumnKind.Boolean),
            new("TcpEnabled", ProxyColumnKind.Boolean),
            new("InstallSharedDirectory", ProxyColumnKind.String),
            new("SqlDomainGroup", ProxyColumnKind.String),
            new("PolicyHealthState", ProxyColumnKind.Int32),
            new("FilestreamLevel", ProxyColumnKind.Int32),
            new("FilestreamShareName", ProxyColumnKind.String),
            new("TapeLoadWaitTime", ProxyColumnKind.Int32),
            new("IsHadrEnabled", ProxyColumnKind.Boolean),
            new("HadrManagerStatus", ProxyColumnKind.Int32),
            new("ClusterName", ProxyColumnKind.String),
            new("ClusterQuorumType", ProxyColumnKind.Int32),
            new("ClusterQuorumState", ProxyColumnKind.Int32),
            new("ServiceAccountSid", ProxyColumnKind.String),
            new("IsPolyBaseInstalled", ProxyColumnKind.Boolean),
            new("Name", ProxyColumnKind.String),
            new("InstanceName", ProxyColumnKind.String),
            new("Status", ProxyColumnKind.Int32),
            new("PathSeparator", ProxyColumnKind.String),
            new("IsContainedAuthentication", ProxyColumnKind.Int32),
            new("ServerType", ProxyColumnKind.Int32),
        };
        writer.WriteColumnMetadata(columns);
        writer.WriteRow(columns, new object?[]
        {
            null, -1, 9, "", null, 1000, "",
            "MSSQLSERVER", "", @"C:\SAP", false, 38, false,
            "8.00.194", "Standard Edition (64-bit)", "RTM", "", false, 2,
            collation, false, Environment.MachineName, Environment.MachineName,
            2, "", "", "", "",
            "8.00.194", null,
            872468488, 196609, (byte)1, "iso_1", (byte)52, "nocase_iso",
            "4.0.30319.42000", "", false, true, "",
            "", 0, 0, "", -1,
            false, 0, "", 4, 3,
            null, false, "SQLPROXY", null, 1,
            @"\", 0, null,
        });
        writer.WriteDone(DoneStatus.Final | DoneStatus.Count, 1);
        return writer.ToArray();
    }

    private static async Task<byte[]> BuildServerRootPropertiesProbeResponse(string sql, AseConnection ase, CancellationToken ct)
    {
        var collation = await GetRealCollationNameAsync(ase, ct);
        var writer = new TokenWriter();
        var columns = new List<ProxyColumn>
        {
            new("IsCaseSensitive", ProxyColumnKind.Boolean),
            new("MaxPrecision", ProxyColumnKind.Int32),
            new("ErrorLogPath", ProxyColumnKind.String),
            new("RootDirectory", ProxyColumnKind.String),
            new("PathSeparator", ProxyColumnKind.String),
            new("IsFullTextInstalled", ProxyColumnKind.Boolean),
            new("MasterDBLogPath", ProxyColumnKind.String),
            new("MasterDBPath", ProxyColumnKind.String),
            new("VersionString", ProxyColumnKind.String),
            new("Edition", ProxyColumnKind.String),
            new("ProductLevel", ProxyColumnKind.String),
            new("IsSingleUser", ProxyColumnKind.Boolean),
            new("EngineEdition", ProxyColumnKind.Int32),
            new("Collation", ProxyColumnKind.String),
            new("NetName", ProxyColumnKind.String),
            new("IsClustered", ProxyColumnKind.Boolean),
            new("ResourceVersionString", ProxyColumnKind.String),
            new("ResourceLastUpdateDateTime", ProxyColumnKind.String),
            new("CollationID", ProxyColumnKind.Int32),
            new("ComparisonStyle", ProxyColumnKind.Int32),
            new("SqlCharSet", ProxyColumnKind.Byte), // real type is tinyint — see CLAUDE.md bug #22
            new("SqlCharSetName", ProxyColumnKind.String),
            new("SqlSortOrder", ProxyColumnKind.Byte), // real type is tinyint — see CLAUDE.md bug #22
            new("SqlSortOrderName", ProxyColumnKind.String),
            new("BuildClrVersionString", ProxyColumnKind.String),
            new("ComputerNamePhysicalNetBIOS", ProxyColumnKind.String),
            new("IsPolyBaseInstalled", ProxyColumnKind.Boolean),
        };
        writer.WriteColumnMetadata(columns);
        writer.WriteRow(columns, new object?[]
        {
            // RootDirectory: real ASE install path on "sqlserver" (192.168.100.20), see root
            // CLAUDE.md — the one field here we actually know for a fact, instead of an empty
            // string. ErrorLogPath/MasterDBLogPath/MasterDBPath left blank rather than guessed
            // exact filenames we haven't verified (a wrong-but-plausible path is worse than an
            // honest "don't know" here).
            false, 38, "", @"C:\SAP", "\\",
            false, "", "",
            "8.00.194", "Standard Edition (64-bit)", "RTM",
            false, 2,
            collation, Environment.MachineName, false,
            "8.00.194", null,
            872468488, 196609, 1, "iso_1", 52, "nocase_iso",
            "4.0.30319.42000", Environment.MachineName, false,
        });
        writer.WriteDone(DoneStatus.Final | DoneStatus.Count, 1);
        return writer.ToArray();
    }

    // "list tables in this database" — see the probe table entry above. ASE has a real, direct
    // equivalent for most of this: sysobjects (type='U') for the table names, sysindexes for
    // clustered/nonclustered presence (indid=1 is ASE's clustered index, indid>1 nonclustered,
    // indid=0 means heap/no clustered index — same convention as real Sybase docs). The genuinely
    // MSSQL-only features (partitioning, sparse columns, XML indexes/columns) have no ASE concept
    // at all, so false is the honest answer there, not a fabricated placeholder.
    //
    // CreateDate uses the real ProxyColumnKind.DateTime (added alongside this probe) and ASE's real
    // sysobjects.crdate — NOT the earlier NULL-as-NVARCHAR workaround. A plain NVARCHAR column here
    // caused exactly the same silent client-side swallow as CLAUDE.md bug #22 (sys.databases.state
    // being INTN where tinyint was expected): the probe matched, the real data came back, ASE never
    // errored, but Object Explorer's "Tables" node still showed nothing and the connection went
    // quiet — a strongly-typed client-side read against the wrong wire type, with nothing surfacing
    // on this end to say so. Schema hardcoded to "dbo" — same convention already used in
    // BuildDatabaseDefaultSchemaProbeResponse (no contained-user schema concept to map from ASE).
    private static async Task<byte[]> BuildTableListProbeResponse(string sql, AseConnection ase, CancellationToken ct)
    {
        var columns = new List<ProxyColumn>
        {
            new("Name", ProxyColumnKind.String),
            new("Schema", ProxyColumnKind.String),
            new("Urn", ProxyColumnKind.String),
            new("CreateDate", ProxyColumnKind.DateTime),
            new("IsPartitioned", ProxyColumnKind.Boolean),
            new("HasSparseColumn", ProxyColumnKind.Boolean),
            new("HasNonClusteredIndex", ProxyColumnKind.Boolean),
            new("HasClusteredIndex", ProxyColumnKind.Boolean),
            new("HasPrimaryClusteredIndex", ProxyColumnKind.Boolean),
            new("HasXmlIndex", ProxyColumnKind.Boolean),
            new("HasXmlData", ProxyColumnKind.Boolean),
        };

        var writer = new TokenWriter();
        writer.WriteColumnMetadata(columns);

        var tables = await GetRealTablesAsync(ase, ct);
        foreach (var t in tables)
        {
            var urn = "Server[@Name='SQLPROXY']/Database[@Name='" + t.DatabaseName + "']/Table[@Name='" +
                      t.Name + "' and @Schema='dbo']";
            writer.WriteRow(columns, new object?[]
            {
                t.Name, "dbo", urn, t.CreateDate,
                false, false,
                t.HasNonClusteredIndex, t.HasClusteredIndex,
                false, false, false,
            });
        }
        writer.WriteDone(DoneStatus.Final | DoneStatus.Count, (ulong)tables.Count);
        return writer.ToArray();
    }

    // Shared by the Columns probe and the generic per-table sub-collection catch-all below — pulls
    // the single table name out of "tbl.name=N'X'" (or "tbl.name='X'"), the common WHERE-clause
    // shape every one of these per-table SMO queries uses.
    private static readonly System.Text.RegularExpressions.Regex TablePropertyNameFilterRegex =
        new(@"tbl\.name\s*=\s*N?'([^']+)'", System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    // Columns probe — see the probe table entry above. Real ASE data via syscolumns/systypes
    // (ASE's direct equivalents of sys.columns/sys.types) for the columns a user actually cares
    // about (name/type/length/precision/scale/nullable). InPrimaryKey now uses real data too
    // (sp_pkeys, same helper as the Keys/Indexes probes below, added 2026-10-26 once TestTabla got
    // a real PK to check against) — IsForeignKey/Computed stay `false`, not verified yet against a
    // real FK/computed-column setup, same simplification already accepted elsewhere in this file.
    private static async Task<byte[]> BuildColumnListProbeResponse(string sql, AseConnection ase, CancellationToken ct)
    {
        var columns = new List<ProxyColumn>
        {
            new("Name", ProxyColumnKind.String),
            new("Urn", ProxyColumnKind.String),
            new("InPrimaryKey", ProxyColumnKind.Boolean),
            new("IsForeignKey", ProxyColumnKind.Boolean),
            new("DataType", ProxyColumnKind.String),
            new("SystemType", ProxyColumnKind.String),
            new("Length", ProxyColumnKind.Int32),
            new("NumericPrecision", ProxyColumnKind.Int32),
            new("NumericScale", ProxyColumnKind.Int32),
            new("Nullable", ProxyColumnKind.Boolean),
            new("Computed", ProxyColumnKind.Boolean),
        };

        var writer = new TokenWriter();
        writer.WriteColumnMetadata(columns);

        var match = TablePropertyNameFilterRegex.Match(sql);
        var rowCount = 0UL;
        if (match.Success)
        {
            var tableName = match.Groups[1].Value;
            var tableRows = await GetRealColumnsAsync(ase, tableName, ct);
            var pkColumns = await GetPrimaryKeyColumnsAsync(ase, tableName, ct);
            foreach (var c in tableRows)
            {
                var urn = "Server[@Name='SQLPROXY']/Database[@Name='" + tableName + "']/Table[@Name='" +
                          tableName + "' and @Schema='dbo']/Column[@Name='" + c.Name + "']";
                writer.WriteRow(columns, new object?[]
                {
                    c.Name, urn, pkColumns.Contains(c.Name), false, c.TypeName, c.TypeName,
                    c.Length, c.Precision, c.Scale, c.Nullable, false,
                });
                rowCount++;
            }
        }
        writer.WriteDone(DoneStatus.Final | DoneStatus.Count, rowCount);
        return writer.ToArray();
    }

    // Sybase ASE's syscolumns.status bit 0x08 is the documented "allows null" flag (same convention
    // since Sybase 10 — distinct from MSSQL's sys.columns.is_nullable, but semantically identical).
    // "number = 0" excludes stored-procedure parameter rows — syscolumns is shared between tables
    // and procs, 0 is the table-column convention.
    private static async Task<List<(string Name, string TypeName, int Length, int Precision, int Scale, bool Nullable, int ColumnId)>> GetRealColumnsAsync(
        AseConnection ase, string tableName, CancellationToken ct)
    {
        var result = new List<(string, string, int, int, int, bool, int)>();
        try
        {
            using var cmd = new AseCommand(
                "SELECT c.name, t.name, c.length, c.prec, c.scale, c.status, c.colid " +
                "FROM syscolumns c JOIN systypes t ON c.usertype = t.usertype " +
                "WHERE c.id = object_id('" + tableName.Replace("'", "''") + "') AND c.number = 0 " +
                "ORDER BY c.colid", ase);
            using var reader = (AseDataReader)await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                var name = reader.GetString(0);
                var typeName = reader.GetString(1);
                var length = Convert.ToInt32(reader.GetValue(2));
                var prec = reader.IsDBNull(3) ? 0 : Convert.ToInt32(reader.GetValue(3));
                var scale = reader.IsDBNull(4) ? 0 : Convert.ToInt32(reader.GetValue(4));
                var status = Convert.ToInt64(reader.GetValue(5));
                var colid = Convert.ToInt32(reader.GetValue(6));
                result.Add((name, typeName, length, prec, scale, (status & 0x08) != 0, colid));
            }
        }
        catch
        {
            // fall through — empty list means the Columns node shows empty rather than erroring
        }
        return result;
    }

    // Recognizes a plain "clmns.<field>" reference, with or without a CAST(... AS sometype) or
    // ISNULL(..., default) wrapper (both of which appear in real captured scripts around these —
    // e.g. "CAST(clmns.is_nullable AS bit)" — without changing which underlying field is wanted).
    private static readonly System.Text.RegularExpressions.Regex ColumnFieldRegex =
        new(@"clmns\.(\w+)\s+AS\s+\[(\w+)\]", System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    // Known sys.all_columns-style fields this proxy can answer for real, mapped from the same
    // syscolumns-backed data GetRealColumnsAsync already fetches for the full Columns probe. Only
    // fields actually backed by real data belong here — anything else must NOT be added just to
    // make a future query match (the whole point of this generic probe is to extend coverage
    // without ever fabricating a field that isn't real).
    private static readonly HashSet<string> KnownColumnFields = new(StringComparer.OrdinalIgnoreCase)
        { "name", "column_id", "max_length", "precision", "scale", "is_nullable" };

    // True only if EVERY "AS [Alias]" in the query is a recognized plain "clmns.<field>" reference
    // (see ColumnFieldRegex/KnownColumnFields) — if the query selects anything else too (a join to
    // systypes, a computed subquery, a literal), this intentionally returns false so the query falls
    // through to a more specific probe (if one matches) or the empty catch-all, rather than this
    // generic probe silently dropping columns it doesn't understand (the exact bug class that broke
    // SMO's bootstrap scripts in CLAUDE.md bugs #8/#17).
    private static bool IsAllPlainColumnFieldSelect(string sql)
    {
        var totalAliases = AllAliasesRegex.Matches(sql).Count;
        if (totalAliases == 0) return false;
        var fieldMatches = ColumnFieldRegex.Matches(sql);
        if (fieldMatches.Count != totalAliases) return false;
        foreach (System.Text.RegularExpressions.Match m in fieldMatches)
            if (!KnownColumnFields.Contains(m.Groups[1].Value)) return false;
        return true;
    }

    // See the probe table entry above — answers any combination of the known plain clmns.<field>
    // columns the query actually asked for (by position, each with the client's own chosen alias),
    // using the same real syscolumns-backed data as the full Columns probe.
    private static async Task<byte[]> BuildGenericColumnFieldProbeResponse(string sql, AseConnection ase, CancellationToken ct)
    {
        var fields = ColumnFieldRegex.Matches(sql)
            .Select(m => (Field: m.Groups[1].Value, Alias: m.Groups[2].Value))
            .ToList();

        var columns = fields.Select(f => new ProxyColumn(f.Alias, f.Field.Equals("is_nullable", StringComparison.OrdinalIgnoreCase)
            ? ProxyColumnKind.Boolean
            : f.Field.Equals("name", StringComparison.OrdinalIgnoreCase) ? ProxyColumnKind.String : ProxyColumnKind.Int32)).ToList();

        var writer = new TokenWriter();
        writer.WriteColumnMetadata(columns);

        var match = TablePropertyNameFilterRegex.Match(sql);
        var rowCount = 0UL;
        if (match.Success)
        {
            var tableRows = await GetRealColumnsAsync(ase, match.Groups[1].Value, ct);
            foreach (var c in tableRows)
            {
                var values = fields.Select(f => f.Field.ToLowerInvariant() switch
                {
                    "name" => (object?)c.Name,
                    "column_id" => c.ColumnId,
                    "max_length" => c.Length,
                    "precision" => c.Precision,
                    "scale" => c.Scale,
                    "is_nullable" => c.Nullable,
                    _ => null,
                }).ToArray();
                writer.WriteRow(columns, values);
                rowCount++;
            }
        }
        writer.WriteDone(DoneStatus.Final | DoneStatus.Count, rowCount);
        return writer.ToArray();
    }

    // sp_pkeys — ASE's own ODBC-catalog system proc, returns one row per primary-key column
    // (table_name, column_name, key_seq, ...). Used instead of decoding sysindexes' undocumented
    // status/status2 bit layout by hand for "is this column/index really the primary key" — a
    // documented, stable proc beats guessing at bit positions (same lesson as CLAUDE.md bug #26,
    // where a guessed bit position turned out to be wrong). Shared by the Columns probe above and
    // the Keys/Indexes probes below so all three never disagree about which columns are the PK.
    private static async Task<HashSet<string>> GetPrimaryKeyColumnsAsync(AseConnection ase, string tableName, CancellationToken ct)
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var cmd = new AseCommand("sp_pkeys '" + tableName.Replace("'", "''") + "'", ase);
            using var reader = (AseDataReader)await cmd.ExecuteReaderAsync(ct);
            var ordinal = reader.GetOrdinal("column_name");
            while (await reader.ReadAsync(ct))
                result.Add(reader.GetString(ordinal));
        }
        catch
        {
            // fall through — empty set means InPrimaryKey/IndexKeyType default to "not a key"
        }
        return result;
    }

    // Real ASE index list for one table (sysindexes, indid 1..254 — excludes the indid=0 "heap"
    // placeholder row and the indid=255 text/image row, neither of which is a real index). IsUnique
    // comes from the documented sysindexes.status bit 0x02 — confirmed against a real PK created
    // this session (status=2066=0x812, and sp_helpindex independently reported "clustered, unique"
    // for that same index, so bit 0x02 checks out). IndexKeyType ("is this the PK, a unique
    // constraint, or just a plain index") has no equally reliable bit to read in this ASE version
    // (no key1../keycnt-based column mapping available to cross-check against sp_pkeys properly —
    // see CLAUDE.md for the full reasoning) — simplified to: the first unique index found, if the
    // table has a real PK per sp_pkeys, is reported as the PK (1); any other unique index as a
    // unique constraint (2); anything else as a plain index (0). Right for the common case (one
    // unique index = the PK) but a table with a PK AND a separate unique index/constraint could
    // report the wrong one as "1" — documented simplification, not verified against that case yet.
    private static async Task<List<(string Name, bool IsUnique, bool IsClustered, int IndexKeyType)>> GetRealIndexesAsync(
        AseConnection ase, string tableName, CancellationToken ct)
    {
        var result = new List<(string, bool, bool, int)>();
        try
        {
            var hasPk = (await GetPrimaryKeyColumnsAsync(ase, tableName, ct)).Count > 0;
            using var cmd = new AseCommand(
                "SELECT name, indid, status FROM sysindexes " +
                "WHERE id = object_id('" + tableName.Replace("'", "''") + "') AND indid BETWEEN 1 AND 254",
                ase);
            using var reader = (AseDataReader)await cmd.ExecuteReaderAsync(ct);
            var assignedPk = false;
            while (await reader.ReadAsync(ct))
            {
                var name = reader.GetString(0);
                var indid = Convert.ToInt32(reader.GetValue(1));
                var status = Convert.ToInt64(reader.GetValue(2));
                var isUnique = (status & 0x02) != 0;
                var isClustered = indid == 1;
                var indexKeyType = isUnique && hasPk && !assignedPk ? 1 : isUnique ? 2 : 0;
                if (indexKeyType == 1) assignedPk = true;
                result.Add((name, isUnique, isClustered, indexKeyType));
            }
        }
        catch
        {
            // fall through — empty list means the Indexes/Keys node shows empty rather than erroring
        }
        return result;
    }

    // "Keys" node — see the probe table entry above. Only the index(es) with IndexKeyType != 0
    // (PK or unique constraint) — real Indexes node below lists everything, this is the filtered
    // SMO subset.
    private static async Task<byte[]> BuildKeyIndexListProbeResponse(string sql, AseConnection ase, CancellationToken ct)
    {
        var columns = new List<ProxyColumn>
        {
            new("Name", ProxyColumnKind.String),
            new("Urn", ProxyColumnKind.String),
            new("IndexKeyType", ProxyColumnKind.Int32),
            new("IndexType", ProxyColumnKind.Int32),
        };
        var writer = new TokenWriter();
        writer.WriteColumnMetadata(columns);

        var match = TablePropertyNameFilterRegex.Match(sql);
        var rowCount = 0UL;
        if (match.Success)
        {
            var tableName = match.Groups[1].Value;
            var indexes = await GetRealIndexesAsync(ase, tableName, ct);
            foreach (var idx in indexes.Where(i => i.IndexKeyType != 0))
            {
                var urn = "Server[@Name='SQLPROXY']/Database[@Name='" + tableName + "']/Table[@Name='" +
                          tableName + "' and @Schema='dbo']/Index[@Name='" + idx.Name + "']";
                writer.WriteRow(columns, new object?[] { idx.Name, urn, idx.IndexKeyType, idx.IsClustered ? 1 : 2 });
                rowCount++;
            }
        }
        writer.WriteDone(DoneStatus.Final | DoneStatus.Count, rowCount);
        return writer.ToArray();
    }

    // "Indexes" node (unfiltered) — see the probe table entry above and GetRealIndexesAsync for the
    // data/simplifications. IndexType here uses the same simplified clustered(1)/nonclustered(2)
    // mapping as IndexKeyType's own IndexType column above — a cosmetic display value for SMO's
    // tree icon, not verified bit-for-bit against its real internal enum (CLAUDE.md).
    private static async Task<byte[]> BuildIndexListProbeResponse(string sql, AseConnection ase, CancellationToken ct)
    {
        var columns = new List<ProxyColumn>
        {
            new("Name", ProxyColumnKind.String),
            new("Urn", ProxyColumnKind.String),
            new("IndexType", ProxyColumnKind.Int32),
            new("IndexKeyType", ProxyColumnKind.Int32),
            new("IsUnique", ProxyColumnKind.Boolean),
        };
        var writer = new TokenWriter();
        writer.WriteColumnMetadata(columns);

        var match = TablePropertyNameFilterRegex.Match(sql);
        var rowCount = 0UL;
        if (match.Success)
        {
            var tableName = match.Groups[1].Value;
            var indexes = await GetRealIndexesAsync(ase, tableName, ct);
            foreach (var idx in indexes)
            {
                var urn = "Server[@Name='SQLPROXY']/Database[@Name='" + tableName + "']/Table[@Name='" +
                          tableName + "' and @Schema='dbo']/Index[@Name='" + idx.Name + "']";
                writer.WriteRow(columns, new object?[] { idx.Name, urn, idx.IsClustered ? 1 : 2, idx.IndexKeyType, idx.IsUnique });
                rowCount++;
            }
        }
        writer.WriteDone(DoneStatus.Final | DoneStatus.Count, rowCount);
        return writer.ToArray();
    }

    // Guesses a plausible TDS type for an unknown "sub-node of one specific table" query's column,
    // from its alias name alone — good enough for a ZERO-ROW response (no value ever gets read
    // against the declared type, so the main risk class from CLAUDE.md bug #22 doesn't apply here;
    // this is just about not leaving a glaringly wrong type in COLMETADATA for the rare client that
    // inspects it before reading rows).
    private static ProxyColumnKind GuessColumnKind(string alias) =>
        alias.Equals("CreateDate", StringComparison.OrdinalIgnoreCase) || alias.EndsWith("Date", StringComparison.OrdinalIgnoreCase)
            ? ProxyColumnKind.DateTime
            : alias.StartsWith("Is", StringComparison.OrdinalIgnoreCase) || alias.StartsWith("Has", StringComparison.OrdinalIgnoreCase)
                ? ProxyColumnKind.Boolean
                : alias.Contains("Type", StringComparison.OrdinalIgnoreCase)
                    ? ProxyColumnKind.Int32
                    : ProxyColumnKind.String;

    // See the probe table entry above — zero rows for every per-table SMO sub-collection this proxy
    // doesn't implement yet (Keys, Indexes, CheckConstraints, DefaultConstraints, EdgeConstraints,
    // Triggers, Statistics, ForeignKeys, ...), with columns/types parsed from the query's own
    // "<expr> AS [Alias]" list instead of a query-shape-specific dedicated probe for each.
    private static byte[] BuildEmptyTableSubCollectionProbeResponse(string sql)
    {
        var aliases = AllAliasesRegex.Matches(sql).Select(m => m.Groups[1].Value).Distinct().ToList();
        var columns = aliases.Count == 0
            ? new List<ProxyColumn> { new("Value", ProxyColumnKind.String) }
            : aliases.Select(a => new ProxyColumn(a, GuessColumnKind(a))).ToList();

        var writer = new TokenWriter();
        writer.WriteColumnMetadata(columns);
        writer.WriteDone(DoneStatus.Final | DoneStatus.Count, 0);
        return writer.ToArray();
    }

    // "System Tables" node variant — see the probe table entry above. Zero rows, correctly typed
    // columns (matters even for an empty result: COLMETADATA still has to declare the right TDS
    // type per column, same lesson as bug #22).
    private static byte[] BuildSystemTableListProbeResponse()
    {
        var columns = new List<ProxyColumn>
        {
            new("Name", ProxyColumnKind.String),
            new("Schema", ProxyColumnKind.String),
            new("Urn", ProxyColumnKind.String),
            new("CreateDate", ProxyColumnKind.DateTime),
            new("IsMemoryOptimized", ProxyColumnKind.Boolean),
            new("HasNonClusteredIndex", ProxyColumnKind.Boolean),
            new("HasClusteredIndex", ProxyColumnKind.Boolean),
            new("HasPrimaryClusteredIndex", ProxyColumnKind.Boolean),
            new("HasXmlIndex", ProxyColumnKind.Boolean),
            new("HasXmlData", ProxyColumnKind.Boolean),
            new("IsNode", ProxyColumnKind.Boolean),
            new("IsEdge", ProxyColumnKind.Boolean),
        };
        var writer = new TokenWriter();
        writer.WriteColumnMetadata(columns);
        writer.WriteDone(DoneStatus.Final | DoneStatus.Count, 0);
        return writer.ToArray();
    }

    // Real ASE table list for whatever database this session's connection is currently using
    // ("use [X]" already ran for real against ASE earlier in the session, same as every other
    // non-probe batch) — sysobjects/sysindexes are ASE's direct equivalents of sys.tables/
    // sys.indexes, crdate is the real creation date. Falls back to an empty list if the query fails
    // for any reason, same defensive pattern as GetRealDatabaseNamesAsync (an empty Tables node
    // beats crashing the connection).
    private static async Task<List<(string Name, string DatabaseName, DateTime? CreateDate, bool HasClusteredIndex, bool HasNonClusteredIndex)>> GetRealTablesAsync(AseConnection ase, CancellationToken ct)
    {
        var result = new List<(string, string, DateTime?, bool, bool)>();
        try
        {
            using var cmd = new AseCommand(
                "SELECT o.name, db_name(), o.crdate, " +
                "(SELECT COUNT(*) FROM sysindexes i WHERE i.id = o.id AND i.indid = 1), " +
                "(SELECT COUNT(*) FROM sysindexes i WHERE i.id = o.id AND i.indid > 1) " +
                "FROM sysobjects o WHERE o.type = 'U' ORDER BY o.name", ase);
            using var reader = (AseDataReader)await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                var name = reader.GetString(0);
                var dbName = reader.GetString(1);
                var createDate = reader.IsDBNull(2) ? (DateTime?)null : Convert.ToDateTime(reader.GetValue(2));
                var clustered = Convert.ToInt64(reader.GetValue(3)) > 0;
                var nonClustered = Convert.ToInt64(reader.GetValue(4)) > 0;
                result.Add((name, dbName, createDate, clustered, nonClustered));
            }
        }
        catch
        {
            // fall through — empty list means the Tables node shows empty rather than erroring
        }
        return result;
    }

    // Generic SERVERPROPERTY('X') handler. Looks up the requested property name in a table of
    // plausible values (consistent with what BuildEditionProbeResponse already claims — same
    // ProductVersion/EngineEdition — so a client that read both doesn't see contradictory answers).
    // Properties we don't know about return NULL, which matches what a real SQL Server does for an
    // unrecognized SERVERPROPERTY name too — a well-formed "I don't know" instead of a parse error.
    private static readonly System.Text.RegularExpressions.Regex ServerPropertyNameRegex =
        new(@"SERVERPROPERTY\s*\(\s*N?'([^']+)'\s*\)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    private static readonly Dictionary<string, object?> ServerPropertyValues = new(StringComparer.OrdinalIgnoreCase)
    {
        ["EngineEdition"] = 2, // Standard — Express was tried (CLAUDE.md bug #41) and reverted: broke the Databases query shape with no confirmed benefit for the Agent crash
        ["Edition"] = "Standard Edition (64-bit)",
        ["EditionID"] = 1872460670L,
        // Deliberately claiming SQL Server 2005 (major version 9) here, not the real-looking "15"
        // used everywhere else until now — see CLAUDE.md bug #33. Policy-Based Management (and the
        // Object Explorer "health state" icon that constructs a PolicyStore for every tree node)
        // was introduced in SQL Server 2008; a pre-2008 VersionMajor should make SMO skip that
        // check entirely instead of attempting it and crashing client-side inside TdsExecuteRPC.
        ["ProductVersion"] = "8.00.194",
        ["ProductLevel"] = "RTM",
        ["ProductMajorVersion"] = "8",
        ["ProductMinorVersion"] = "00",
        ["ProductBuild"] = "194",
        ["ProductUpdateLevel"] = "",
        // "Collation" is deliberately absent — BuildGenericServerPropertyResponse special-cases it
        // to query the real ASE value instead (GetRealCollationNameAsync).
        ["ServerName"] = "SQLPROXY",
        ["MachineName"] = Environment.MachineName,
        ["ComputerNamePhysicalNetBIOS"] = Environment.MachineName,
        ["InstanceName"] = null,
        ["IsClustered"] = 0,
        ["IsHadrEnabled"] = 0,
        ["IsIntegratedSecurityOnly"] = 0,
        ["FilestreamConfiguredLevel"] = 0,
        ["ProcessID"] = Environment.ProcessId,
    };

    // SMO's bootstrap "full server properties" final SELECT — column set VARIES by claimed edition
    // (see CLAUDE.md bug #41: [Server_Status] is present for Standard, absent for Express). Build
    // the column/value lists by checking which aliases the real query text actually contains,
    // instead of assuming a fixed 15-column shape that only matched one variant.
    private static byte[] BuildFullServerPropertiesProbeResponse(string sql)
    {
        var writer = new TokenWriter();
        var columns = new List<ProxyColumn> { new("Server_Name", ProxyColumnKind.String), new("Server_Urn", ProxyColumnKind.String), new("Server_ServerType", ProxyColumnKind.Int32) };
        var values = new List<object?> { "SQLPROXY", "Server[@Name='SQLPROXY']", null };

        if (sql.Contains("[Server_Status]", StringComparison.OrdinalIgnoreCase))
        {
            columns.Add(new("Server_Status", ProxyColumnKind.Int32));
            values.Add(1);
        }

        columns.AddRange(new[]
        {
            new ProxyColumn("Server_IsContainedAuthentication", ProxyColumnKind.Int32),
            new ProxyColumn("VersionMajor", ProxyColumnKind.Int32),
            new ProxyColumn("VersionMinor", ProxyColumnKind.Int32),
            new ProxyColumn("BuildNumber", ProxyColumnKind.Int32),
            new ProxyColumn("IsSingleUser", ProxyColumnKind.Boolean),
            new ProxyColumn("Edition", ProxyColumnKind.String),
            new ProxyColumn("EngineEdition", ProxyColumnKind.Int32),
            new ProxyColumn("IsXTPSupported", ProxyColumnKind.Boolean),
            new ProxyColumn("VersionString", ProxyColumnKind.String),
            new ProxyColumn("HostPlatform", ProxyColumnKind.String),
            new ProxyColumn("IsFullTextInstalled", ProxyColumnKind.Boolean),
        });
        values.AddRange(new object?[]
        {
            0,
            8, 0, 194, false,
            "Standard Edition (64-bit)", 2, false,
            "8.00.194", "Windows", false,
        });

        writer.WriteColumnMetadata(columns);
        writer.WriteRow(columns, values.ToArray());
        writer.WriteDone(DoneStatus.Final | DoneStatus.Count, 1);
        return writer.ToArray();
    }

    // Bracketed alias immediately following a SERVERPROPERTY(...) call (possibly through a
    // CAST(... AS sometype) wrapper — that inner "AS int"/"AS bit" is a type name, never
    // bracket-quoted, so requiring brackets here skips right over it to the real column alias).
    private static readonly System.Text.RegularExpressions.Regex AliasRegex =
        new(@"AS\s*\[([^\]]+)\]", System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    // A query can ask for several properties as separate columns in one row, e.g.
    // "SELECT SERVERPROPERTY('Edition') AS [Edition], SERVERPROPERTY('Collation') AS [Collation]"
    // — the first version of this probe only ever returned ONE column (whatever the first
    // SERVERPROPERTY(...) in the text was), silently dropping the rest. That columncount mismatch
    // is exactly what broke SMO downstream ("Couldn't store <...> in Server_ServerType Column":
    // values landed in the wrong ordinal once the shapes stopped matching). Fix: handle every
    // SERVERPROPERTY(...) occurrence in the text, in order, as its own column.
    private static async Task<byte[]> BuildGenericServerPropertyResponse(string sql, AseConnection ase, CancellationToken ct)
    {
        var matches = ServerPropertyNameRegex.Matches(sql);
        var columns = new List<ProxyColumn>();
        var values = new List<object?>();

        foreach (System.Text.RegularExpressions.Match match in matches)
        {
            var propertyName = match.Groups[1].Value;
            // Real ASE data instead of the fabricated MSSQL-shaped default — see
            // GetRealCollationNameAsync.
            var value = propertyName.Equals("Collation", StringComparison.OrdinalIgnoreCase)
                ? await GetRealCollationNameAsync(ase, ct)
                : ServerPropertyValues.TryGetValue(propertyName, out var known) ? known : null;

            // Look for a bracketed alias between the end of this call and the next one (or end of
            // string) — same bounded-window heuristic, scoped so an alias doesn't bleed into the
            // next column when there are several on one line.
            var next = match.NextMatch();
            var searchEnd = next.Success ? next.Index : sql.Length;
            var window = sql[(match.Index + match.Length)..searchEnd];
            var aliasMatch = AliasRegex.Match(window);
            var columnName = aliasMatch.Success ? aliasMatch.Groups[1].Value : propertyName;

            var kind = value switch
            {
                int or long => ProxyColumnKind.Int32,
                bool => ProxyColumnKind.Boolean,
                _ => ProxyColumnKind.String,
            };

            columns.Add(new ProxyColumn(columnName, kind));
            values.Add(value);
        }

        if (columns.Count == 0)
            columns.Add(new ProxyColumn("Value", ProxyColumnKind.String));
        if (values.Count == 0)
            values.Add(null);

        var writer = new TokenWriter();
        writer.WriteColumnMetadata(columns);
        writer.WriteRow(columns, values.ToArray());
        writer.WriteDone(DoneStatus.Final | DoneStatus.Count, 1);
        return writer.ToArray();
    }

    private static readonly System.Text.RegularExpressions.Regex ConfigurationIdRegex =
        new(@"configuration_id\s*=\s*(\d+)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    // "select value_in_use from sys.configurations where configuration_id = N" — single scalar,
    // looked up from the same real dataset as the full dump below so the two never disagree.
    private static byte[] BuildConfigValueInUseProbeResponse(string sql)
    {
        var match = ConfigurationIdRegex.Match(sql);
        var value = match.Success && int.TryParse(match.Groups[1].Value, out var id)
            ? RealSysConfigurations.FirstOrDefault(c => c.Id == id).ValueInUse
            : 0;
        return BuildScalarResponse(value);
    }

    // SMO eagerly populates the server's "Configuration" property collection right after
    // connecting, by reading sys.configurations — doesn't exist in ASE. Returning zero rows here
    // crashed SMO later with a NullReferenceException ("Alter failed") — it apparently expects its
    // fixed set of known sp_configure properties to actually be present, not just "empty is fine".
    // So instead of fabricating guessed rows, this is the REAL sys.configurations dump (95 rows,
    // SQL Server 2022) pulled from the actual DEVELOP SQL Server at 192.168.100.20 — exact names,
    // ids, min/max, dynamic/advanced flags and descriptions, so SMO finds every property it expects.
    private static byte[] BuildConfigurationsProbeResponse()
    {
        var writer = new TokenWriter();
        var columns = new List<ProxyColumn>
        {
            new("Name", ProxyColumnKind.String),
            new("Number", ProxyColumnKind.Int32),
            new("Minimum", ProxyColumnKind.Int32),
            new("Maximum", ProxyColumnKind.Int32),
            new("Dynamic", ProxyColumnKind.Boolean),
            new("Advanced", ProxyColumnKind.Boolean),
            new("ConfigValue", ProxyColumnKind.Int32),
            new("RunValue", ProxyColumnKind.Int32),
            new("Description", ProxyColumnKind.String),
        };
        writer.WriteColumnMetadata(columns);
        foreach (var row in RealSysConfigurations)
        {
            writer.WriteRow(columns, new object?[]
            {
                row.Name, row.Id, row.Min, row.Max, row.Dynamic, row.Advanced, row.Value, row.ValueInUse, row.Description,
            });
        }
        writer.WriteDone(DoneStatus.Final | DoneStatus.Count, (ulong)RealSysConfigurations.Length);
        return writer.ToArray();
    }

    // SMO's Configuration.Alter() writes config changes back via "EXEC sys.sp_configure N'...',
    // N'...'" (+ a following "RECONFIGURE"), e.g. temporarily flipping 'show advanced options' or
    // 'SMO and DMO XPs' on to read some other property. ASE parses "sys." as a login/user name
    // (it doesn't have MSSQL's schema-qualified system-proc convention) and fails with "User name
    // 'sys' not found" — there's nothing real to apply on the ASE side anyway, so just ack success.
    private static byte[] BuildNoOpSuccessResponse()
    {
        var writer = new TokenWriter();
        writer.WriteDone(DoneStatus.Final, 0); // no DONE_COUNT — "not applicable", same reasoning as the sqlcmd fix
        return writer.ToArray();
    }

    private static readonly (string Name, int Id, int Min, int Max, bool Dynamic, bool Advanced, int Value, int ValueInUse, string Description)[] RealSysConfigurations =
    {
        ("recovery interval (min)", 101, 0, 32767, true, true, 0, 0, "Maximum recovery interval in minutes"),
        ("allow updates", 102, 0, 1, true, false, 0, 0, "Allow updates to system tables"),
        ("user connections", 103, 0, 32767, false, true, 0, 0, "Number of user connections allowed"),
        ("locks", 106, 5000, 2147483647, false, true, 0, 0, "Number of locks for all users"),
        ("open objects", 107, 0, 2147483647, false, true, 0, 0, "Number of open database objects"),
        ("fill factor (%)", 109, 0, 100, false, true, 0, 0, "Default fill factor percentage"),
        ("disallow results from triggers", 114, 0, 1, true, true, 0, 0, "Disallow returning results from triggers"),
        ("nested triggers", 115, 0, 1, true, false, 1, 1, "Allow triggers to be invoked within triggers"),
        ("server trigger recursion", 116, 0, 1, true, false, 1, 1, "Allow recursion for server level triggers"),
        ("remote access", 117, 0, 1, false, false, 1, 1, "Allow remote access"),
        ("default language", 124, 0, 9999, true, false, 0, 0, "default language"),
        ("cross db ownership chaining", 400, 0, 1, true, false, 0, 0, "Allow cross db ownership chaining"),
        ("max worker threads", 503, 128, 65535, true, true, 0, 0, "Maximum worker threads"),
        ("network packet size (B)", 505, 512, 32767, true, true, 4096, 4096, "Network packet size"),
        ("show advanced options", 518, 0, 1, true, false, 1, 1, "show advanced options"),
        ("remote proc trans", 542, 0, 1, true, false, 0, 0, "Create DTC transaction for remote procedures"),
        ("c2 audit mode", 544, 0, 1, false, true, 0, 0, "c2 audit mode"),
        ("default full-text language", 1126, 0, 2147483647, true, true, 1033, 1033, "default full-text language"),
        ("two digit year cutoff", 1127, 1753, 9999, true, true, 2049, 2049, "two digit year cutoff"),
        ("index create memory (KB)", 1505, 704, 2147483647, true, true, 0, 0, "Memory for index create sorts (kBytes)"),
        ("priority boost", 1517, 0, 1, false, true, 0, 0, "Priority boost"),
        ("remote login timeout (s)", 1519, 0, 2147483647, true, false, 10, 10, "remote login timeout"),
        ("remote query timeout (s)", 1520, 0, 2147483647, true, false, 600, 600, "remote query timeout"),
        ("cursor threshold", 1531, -1, 2147483647, true, true, -1, -1, "cursor threshold"),
        ("set working set size", 1532, 0, 1, false, true, 0, 0, "set working set size"),
        ("user options", 1534, 0, 32767, true, false, 0, 0, "user options"),
        ("affinity mask", 1535, -2147483648, 2147483647, true, true, 0, 0, "affinity mask"),
        ("max text repl size (B)", 1536, -1, 2147483647, true, false, 65536, 65536, "Maximum size of a text field in replication."),
        ("media retention", 1537, 0, 365, true, true, 0, 0, "Tape retention period in days"),
        ("cost threshold for parallelism", 1538, 0, 32767, true, true, 5, 5, "cost threshold for parallelism"),
        ("max degree of parallelism", 1539, 0, 32767, true, true, 2, 2, "maximum degree of parallelism"),
        ("min memory per query (KB)", 1540, 512, 2147483647, true, true, 1024, 1024, "minimum memory per query (kBytes)"),
        ("query wait (s)", 1541, -1, 2147483647, true, true, -1, -1, "maximum time to wait for query memory (s)"),
        ("min server memory (MB)", 1543, 0, 2147483647, true, true, 0, 16, "Minimum size of server memory (MB)"),
        ("max server memory (MB)", 1544, 128, 2147483647, true, true, 2147483647, 2147483647, "Maximum size of server memory (MB)"),
        ("query governor cost limit", 1545, 0, 2147483647, true, true, 0, 0, "Maximum estimated cost allowed by query governor"),
        ("lightweight pooling", 1546, 0, 1, false, true, 0, 0, "User mode scheduler uses lightweight pooling"),
        ("scan for startup procs", 1547, 0, 1, false, true, 0, 0, "scan for startup stored procedures"),
        ("affinity64 mask", 1549, -2147483648, 2147483647, true, true, 0, 0, "affinity64 mask"),
        ("affinity I/O mask", 1550, -2147483648, 2147483647, false, true, 0, 0, "affinity I/O mask"),
        ("affinity64 I/O mask", 1551, -2147483648, 2147483647, false, true, 0, 0, "affinity64 I/O mask"),
        ("transform noise words", 1555, 0, 1, true, true, 0, 0, "Transform noise words for full-text query"),
        ("precompute rank", 1556, 0, 1, true, true, 0, 0, "Use precomputed rank for full-text query"),
        ("PH timeout (s)", 1557, 1, 3600, true, true, 60, 60, "DB connection timeout for full-text protocol handler (s)"),
        ("clr enabled", 1562, 0, 1, true, false, 1, 1, "CLR user code execution enabled in the server"),
        ("max full-text crawl range", 1563, 0, 256, true, true, 4, 4, "Maximum  crawl ranges allowed in full-text indexing"),
        ("ft notify bandwidth (min)", 1564, 0, 32767, true, true, 0, 0, "Number of reserved full-text notifications buffers"),
        ("ft notify bandwidth (max)", 1565, 0, 32767, true, true, 100, 100, "Max number of full-text notifications buffers"),
        ("ft crawl bandwidth (min)", 1566, 0, 32767, true, true, 0, 0, "Number of reserved full-text crawl buffers"),
        ("ft crawl bandwidth (max)", 1567, 0, 32767, true, true, 100, 100, "Max number of full-text crawl buffers"),
        ("default trace enabled", 1568, 0, 1, true, true, 1, 1, "Enable or disable the default trace"),
        ("blocked process threshold (s)", 1569, 0, 86400, true, true, 0, 0, "Blocked process reporting threshold"),
        ("in-doubt xact resolution", 1570, 0, 2, true, true, 0, 0, "Recovery policy for DTC transactions with unknown outcome"),
        ("remote admin connections", 1576, 0, 1, true, false, 0, 0, "Dedicated Admin Connections are allowed from remote clients"),
        ("common criteria compliance enabled", 1577, 0, 1, false, true, 0, 0, "Common Criteria compliance mode enabled"),
        ("EKM provider enabled", 1578, 0, 1, true, true, 0, 0, "Enable or disable EKM provider"),
        ("backup compression default", 1579, 0, 1, true, false, 0, 0, "Enable compression of backups by default"),
        ("filestream access level", 1580, 0, 2, true, false, 0, 0, "Sets the FILESTREAM access level"),
        ("optimize for ad hoc workloads", 1581, 0, 1, true, true, 0, 0, "When this option is set, plan cache size is further reduced for single-use adhoc OLTP workload."),
        ("access check cache bucket count", 1582, 0, 65536, true, true, 0, 0, "Default hash bucket count for the access check result security cache"),
        ("access check cache quota", 1583, 0, 2147483647, true, true, 0, 0, "Default quota for the access check result security cache"),
        ("backup checksum default", 1584, 0, 1, true, false, 0, 0, "Enable checksum of backups by default"),
        ("automatic soft-NUMA disabled", 1585, 0, 1, false, true, 0, 0, "Automatic soft-NUMA is enabled by default"),
        ("external scripts enabled", 1586, 0, 1, true, false, 0, 0, "Allows execution of external scripts"),
        ("clr strict security", 1587, 0, 1, true, true, 0, 0, "CLR strict security enabled in the server"),
        ("column encryption enclave type", 1588, 0, 2, false, false, 0, 0, "Type of enclave used for computations on encrypted columns"),
        ("tempdb metadata memory-optimized", 1589, 0, 1, false, true, 0, 0, "Tempdb metadata memory-optimized is disabled by default."),
        ("ADR cleaner retry timeout (min)", 1591, 0, 32767, true, true, 15, 15, "ADR cleaner retry timeout."),
        ("ADR Preallocation Factor", 1592, 0, 32767, true, true, 4, 4, "ADR Preallocation Factor."),
        ("version high part of SQL Server", 1593, -2147483648, 2147483647, true, true, 1048576, 1048576, "version high part of SQL Server that model database copied for"),
        ("version low part of SQL Server", 1594, -2147483648, 2147483647, true, true, 77987842, 77987842, "version low part of SQL Server that model database copied for"),
        ("Data processed daily limit in TB", 1595, 0, 2147483647, true, false, 2147483647, 2147483647, "SQL On-demand data processed daily limit in TB"),
        ("Data processed weekly limit in TB", 1596, 0, 2147483647, true, false, 2147483647, 2147483647, "SQL On-demand data processed weekly limit in TB"),
        ("Data processed monthly limit in TB", 1597, 0, 2147483647, true, false, 2147483647, 2147483647, "SQL On-demand data processed monthly limit in TB"),
        ("ADR Cleaner Thread Count", 1598, 1, 32767, true, true, 1, 1, "Max number of threads ADR cleaner can assign."),
        ("hardware offload enabled", 1599, 0, 1, false, true, 0, 0, "Enable hardware offloading on the server"),
        ("hardware offload config", 1600, 0, 255, false, true, 0, 0, "Configure hardware offload accelerator"),
        ("hardware offload mode", 1601, 0, 255, false, true, 0, 0, "Configure hardware offload accelerator mode"),
        ("backup compression algorithm", 1602, 0, 2, true, false, 0, 0, "Configure default backup compression algorithm"),
        ("Agent XPs", 16384, 0, 1, true, true, 1, 1, "Enable or disable Agent XPs"),
        ("Database Mail XPs", 16386, 0, 1, true, true, 0, 0, "Enable or disable Database Mail XPs"),
        ("SMO and DMO XPs", 16387, 0, 1, true, true, 1, 1, "Enable or disable SMO and DMO XPs"),
        ("Ole Automation Procedures", 16388, 0, 1, true, true, 0, 0, "Enable or disable Ole Automation Procedures"),
        ("xp_cmdshell", 16390, 0, 1, true, true, 0, 0, "Enable or disable command shell"),
        ("Ad Hoc Distributed Queries", 16391, 0, 1, true, true, 0, 0, "Enable or disable Ad Hoc Distributed Queries"),
        ("Replication XPs", 16392, 0, 1, true, true, 0, 0, "Enable or disable Replication XPs"),
        ("contained database authentication", 16393, 0, 1, true, false, 0, 0, "Enables contained databases and contained authentication"),
        ("hadoop connectivity", 16394, 0, 8, true, false, 0, 0, "Configure SQL Server to connect to external Hadoop or Microsoft Azure storage blob data sources through PolyBase"),
        ("polybase network encryption", 16395, 0, 1, true, true, 1, 1, "Configure SQL Server to encrypt control and data channels when using PolyBase"),
        ("remote data archive", 16396, 0, 1, true, false, 0, 0, "Allow the use of the REMOTE_DATA_ARCHIVE data access for databases"),
        ("allow polybase export", 16397, 0, 1, true, false, 0, 0, "Allows writing into an external table using PolyBase"),
        ("allow filesystem enumeration", 16398, 0, 1, true, true, 1, 1, "Allow enumeration of filesystem"),
        ("polybase enabled", 16399, 0, 1, true, false, 0, 0, "Configure SQL Server to connect to external data sources through PolyBase"),
        ("suppress recovery model errors", 16400, 0, 1, true, true, 0, 0, "Return warning instead of error for unsupported ALTER DATABASE SET RECOVERY command"),
        ("openrowset auto_create_statistics", 16401, 0, 1, true, true, 1, 1, "Enable or disable auto create statistics for openrowset sources."),
    };
}
