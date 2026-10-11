// OpenDLP Agent (macOS / Linux) - GPL-3.0-only
//
// Usage:
//   opendlp-agent [--config /path/agent.config.json]     run (launchd / systemd start it as root)
//   opendlp-agent --decrypt <logfile> [--config ...]      print a local encrypted log
//
// Config lookup: --config, then agent.config.json next to the binary, then the data folder
// (/Library/Application Support/OpenDLP on macOS, /var/lib/opendlp on Linux).

using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace OpenDLP.Agent;

internal static class UnixProgram
{
    private static int Main(string[] args)
    {
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        Directory.SetCurrentDirectory(AppContext.BaseDirectory);

        var configPath = Arg(args, "--config")
            ?? new[] { Path.Combine(AppContext.BaseDirectory, "agent.config.json"), Path.Combine(AgentConfig.DataRoot, "agent.config.json") }
                .FirstOrDefault(File.Exists)
            ?? Path.Combine(AgentConfig.DataRoot, "agent.config.json");

        AgentConfig config;
        try { config = AgentConfig.Load(configPath); }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Config error ({configPath}): {ex.Message}");
            return 2;
        }

        var decrypt = Arg(args, "--decrypt");
        if (decrypt != null)
        {
            var key = config.DeriveLogKey();
            foreach (var line in File.ReadLines(decrypt))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                try { Console.WriteLine(SecureLog.Decrypt(line, key)); }
                catch { Console.WriteLine("[corrupted or tampered line]"); }
            }
            return 0;
        }

        Console.WriteLine($"OpenDLP Endpoint Agent v{AgentVersion.Value} ({(OperatingSystem.IsMacOS() ? "macOS" : "Linux")}) | GPLv3");
        Console.WriteLine($"Config: {configPath}");

        var builder = Host.CreateApplicationBuilder(Array.Empty<string>());
        builder.Services.AddSingleton(config);
        builder.Services.AddHostedService<UnixAgentWorker>();
        builder.Build().Run();
        return 0;
    }

    private static string? Arg(string[] args, string name)
    {
        var i = Array.IndexOf(args, name);
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
    }
}

public sealed class UnixAgentWorker : BackgroundService
{
    private readonly AgentConfig _cfg;
    public UnixAgentWorker(AgentConfig cfg) => _cfg = cfg;

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        var disposables = new List<IDisposable>();
        try
        {
            var policy = new PolicyStore(_cfg.PolicyCachePath, Path.Combine(AppContext.BaseDirectory, "policy.default.json"));
            policy.LoadFromDisk();
            var scanner = new ContentScanner(policy);

            Directory.CreateDirectory(_cfg.LogDirectory);
            var key = _cfg.DeriveLogKey();
            var secure = new SecureLog(_cfg.LogDirectory, "events-agent", key);
            var logger = new CompositeAlertLogger(new ConsoleAlertLogger(), new FileAlertLogger(secure));
            logger.Info("AGENT", $"Started agent={_cfg.AgentId} os={(OperatingSystem.IsMacOS() ? "macOS" : "Linux")} policyVersion={policy.Current.Version}");
            logger.Info("AGENT", $"Paths={string.Join(" | ", _cfg.SensitivePaths)}");

            if (_cfg.TelemetryEnabled && _cfg.ServerUrl.Length > 0 && _cfg.ApiToken.Length > 0)
            {
                var client = new ServerClient(_cfg);
                disposables.Add(client);
                var outbox = new DiskOutbox(_cfg.LogDirectory, "events-agent", key);
                _ = Task.Run(() => client.RunUploadLoopAsync(outbox, logger, ct), ct);
                _ = Task.Run(() => client.RunPolicyLoopAsync(policy, _cfg.PolicyPollSeconds, logger, ct), ct);
                logger.Info("AGENT", $"Telemetry -> {_cfg.ServerUrl}");
            }
            else
            {
                logger.Warn("AGENT", _cfg.EnrollmentCode.Length > 0 && _cfg.ApiToken.Length == 0
                    ? "Enrollment did not succeed yet: running local-only; will retry at next start"
                    : "Telemetry disabled or ServerUrl/ApiToken missing: running local-only with the cached/default policy");
            }

            _ = Task.Run(() => HeartbeatLoop(Path.Combine(_cfg.LogDirectory, "agent.heartbeat"), ct), ct);
            _ = Task.Run(() => RetentionLoop(_cfg.LogDirectory, _cfg.LogRetentionDays, ct), ct);

            var rapid = new RapidActionDetector(logger, _cfg.RapidWindowSeconds, _cfg.RapidThreshold);
            var files = new FileMonitor(_cfg.SensitivePaths, new MagicBytesChecker(), rapid, new EntropyAnalyzer(),
                scanner, logger, _cfg.HighEntropyThreshold, _cfg.MaxScanBytes, _cfg.LogDirectory);
            disposables.Add(files);
            files.Start();

            var volumes = new VolumeMonitor(logger, policy, files);
            _ = Task.Run(() => volumes.RunAsync(ct), ct);

            try { await Task.Delay(Timeout.Infinite, ct); }
            catch (OperationCanceledException) { }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Fatal: {ex}");
            throw;
        }
        finally
        {
            foreach (var d in disposables) { try { d.Dispose(); } catch { } }
        }
    }

    private static async Task HeartbeatLoop(string path, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try { await File.WriteAllTextAsync(path, DateTime.UtcNow.ToString("o"), ct); }
            catch (OperationCanceledException) { break; }
            catch { }
            try { await Task.Delay(3000, ct); } catch (OperationCanceledException) { break; }
        }
    }

    private static async Task RetentionLoop(string dir, int days, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            SecureLog.Purge(dir, days);
            try { await Task.Delay(TimeSpan.FromHours(6), ct); } catch (OperationCanceledException) { break; }
        }
    }
}
