using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Yarp.ReverseProxy.Forwarder;

if (args.Length != 2 || args[0] != "--config")
{
    Console.Error.WriteLine("Usage: SecureGateway.Yarp --config <lab.json>");
    return 2;
}

var startupStage = "configuration";
try
{
    var configFile = Path.GetFullPath(args[1]);
    var settings = JsonSerializer.Deserialize<Settings>(File.ReadAllText(configFile))
        ?? throw new InvalidOperationException("configuration_invalid");
    if (!settings.LabOnly || settings.ListenPort is < 1024 or > 65535
        || !Uri.TryCreate(settings.Destination, UriKind.Absolute, out var destination)
        || destination.Scheme is not ("http" or "https")
        || !destination.IsLoopback || destination.AbsolutePath != "/"
        || destination.Query.Length != 0 || destination.Fragment.Length != 0
        || destination.UserInfo.Length != 0)
        throw new InvalidOperationException("only_fixed_loopback_lab_destinations_are_enabled");

    var builder = WebApplication.CreateBuilder(Array.Empty<string>());
    builder.Logging.ClearProviders(); // Never log bodies, headers, cookies or URL queries.
    builder.WebHost.ConfigureKestrel(options => {
        options.Listen(IPAddress.Loopback, settings.ListenPort);
        options.Limits.MaxRequestBodySize = 1024 * 1024;
        options.Limits.MaxConcurrentConnections = 16;
        options.Limits.MaxConcurrentUpgradedConnections = 8;
        options.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(10);
    });
    builder.Services.AddHttpForwarder();
    var handler = new SocketsHttpHandler {
        UseProxy = false, UseCookies = false, AllowAutoRedirect = false,
        ConnectTimeout = TimeSpan.FromSeconds(5), MaxConnectionsPerServer = 8,
        SslOptions = new SslClientAuthenticationOptions {
            EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12
                | System.Security.Authentication.SslProtocols.Tls13
        }
    };
    if (settings.TrustedRootFile is not null)
    {
        if (destination.Scheme != "https" || settings.TrustedRootSha256 is null)
            throw new InvalidOperationException("trusted_root_fingerprint_required");
        var rootFile = Path.GetFullPath(settings.TrustedRootFile, Path.GetDirectoryName(configFile)!);
        startupStage = "trusted_root";
        var root = X509CertificateLoader.LoadCertificateFromFile(rootFile);
        var fingerprint = Convert.ToHexString(SHA256.HashData(root.RawData));
        if (!fingerprint.Equals(settings.TrustedRootSha256, StringComparison.OrdinalIgnoreCase)
            || root.Subject != root.Issuer
            || !root.Extensions.OfType<X509BasicConstraintsExtension>().Any(x => x.CertificateAuthority))
            throw new InvalidOperationException("trusted_root_invalid");
        var chain = new X509ChainPolicy {
            TrustMode = X509ChainTrustMode.CustomRootTrust,
            // Lab CA has no CRL service. Chain, dates and hostname remain validated.
            RevocationMode = X509RevocationMode.NoCheck
        };
        chain.CustomTrustStore.Add(root);
        handler.SslOptions.CertificateChainPolicy = chain;
    }
    else if (settings.TrustedRootSha256 is not null)
        throw new InvalidOperationException("trusted_root_file_required");
    using var invoker = new HttpMessageInvoker(handler, disposeHandler: true);
    using var slots = new SemaphoreSlim(8);
    startupStage = "listener";
    var app = builder.Build();
    app.UseWebSockets();
    var forwarder = app.Services.GetRequiredService<IHttpForwarder>();
    var transformer = new LabTransformer(destination);
    var requestConfig = new ForwarderRequestConfig { ActivityTimeout = TimeSpan.FromSeconds(30) };
    app.Run(async context => {
        if (context.Request.Host.Host is not ("localhost" or "127.0.0.1")
            || context.Request.Host.Port != settings.ListenPort)
        {
            context.Response.StatusCode = 421;
            return;
        }
        if (context.Request.Method is not ("GET" or "HEAD" or "POST" or "PUT" or "PATCH" or "DELETE" or "OPTIONS"))
        {
            context.Response.StatusCode = 405;
            return;
        }
        if (context.Request.Path == "/_health")
        {
            await context.Response.WriteAsJsonAsync(new { ready = true, mode = "loopback-lab", upstream_tls = destination.Scheme == "https" });
            return;
        }
        if (!await slots.WaitAsync(0, context.RequestAborted))
        {
            context.Response.StatusCode = 429;
            return;
        }
        var clock = Stopwatch.StartNew();
        try
        {
            var error = await forwarder.SendAsync(context, destination.AbsoluteUri, invoker, requestConfig, transformer);
            Console.WriteLine(JsonSerializer.Serialize(new {
                @event = "yarp_request_finished", method = context.Request.Method,
                status = context.Response.StatusCode, elapsed_ms = clock.ElapsedMilliseconds,
                outcome = error.ToString()
            }));
        }
        catch (Exception)
        {
            if (!context.Response.HasStarted) context.Response.StatusCode = 502;
            Console.WriteLine("{\"event\":\"yarp_request_failed\",\"reason\":\"forwarding_failed\"}");
        }
        finally { slots.Release(); }
    });
    Console.WriteLine(JsonSerializer.Serialize(new { @event = "yarp_lab_started", port = settings.ListenPort,
        upstream_tls = destination.Scheme == "https" }));
    await app.RunAsync();
    return 0;
}
catch (Exception error)
{
    Console.Error.WriteLine(JsonSerializer.Serialize(new { @event = "yarp_start_failed",
        reason = "configuration_or_startup_invalid", stage = startupStage, error_type = error.GetType().Name }));
    return 1;
}

sealed class Settings
{
    public int ListenPort { get; set; } = 18766;
    public string Destination { get; set; } = "http://127.0.0.1:18765/";
    public bool LabOnly { get; set; } = true;
    public string? TrustedRootFile { get; set; }
    public string? TrustedRootSha256 { get; set; }
}

sealed class LabTransformer(Uri destination) : HttpTransformer
{
    public override async ValueTask TransformRequestAsync(HttpContext context, HttpRequestMessage request,
        string destinationPrefix, CancellationToken cancellationToken)
    {
        await base.TransformRequestAsync(context, request, destinationPrefix, cancellationToken);
        request.Headers.Host = null;
        foreach (var name in request.Headers.Select(x => x.Key).Where(x =>
            x.StartsWith("X-Forwarded-", StringComparison.OrdinalIgnoreCase)
            || x.Equals("Forwarded", StringComparison.OrdinalIgnoreCase)
            || x.Equals("Proxy-Authorization", StringComparison.OrdinalIgnoreCase)).ToArray())
            request.Headers.Remove(name);
    }
    public override async ValueTask<bool> TransformResponseAsync(HttpContext context,
        HttpResponseMessage? response, CancellationToken cancellationToken)
    {
        var copyBody = await base.TransformResponseAsync(context, response, cancellationToken);
        if (response?.Headers.Location is { } location)
        {
            var resolved = new Uri(destination, location);
            if (resolved.Scheme != destination.Scheme || resolved.Authority != destination.Authority)
            {
                context.Response.Headers.Clear();
                context.Response.StatusCode = 502;
                context.Response.ContentLength = 0;
                return false;
            }
            context.Response.Headers.Location = resolved.PathAndQuery + resolved.Fragment;
        }
        return copyBody;
    }
}
