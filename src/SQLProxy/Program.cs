using System.Text;
using SQLProxy;

// AdoNetCore.AseClient never registers this itself — without it, any ASE server whose default
// charset is a legacy code page (e.g. cp850, windows-1252) fails to open with
// "Server environment changed to unsupported charset '...'" (see AseClient/DECISIONS.md).
Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddWindowsService(options => options.ServiceName = "SQLProxy");

builder.Services
    .AddOptions<ProxiesOptions>()
    .Bind(builder.Configuration);

var comparisonLogPath = builder.Configuration.GetValue<string>("ComparisonLog:Path") ?? "sqlproxy_comparisons.jsonl";
builder.Services.AddSingleton<IQueryComparisonLog>(new JsonlQueryComparisonLog(comparisonLogPath));
builder.Services.AddHostedService<Worker>();

var host = builder.Build();
host.Run();
