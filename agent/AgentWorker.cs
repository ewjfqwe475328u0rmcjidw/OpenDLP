// Leakwarden Agent - GPL-3.0-only
using Microsoft.Extensions.Hosting;

namespace Leakwarden.Agent;

public enum RunMode
{
    /// <summary>Windows service (SYSTEM): files, USB, print, telemetry, policy, helper pipe.</summary>
    Service,
    /// <summary>Everything in one foreground process (development / quick tests).</summary>
    Console,
    /// <summary>Per-user hidden process: clipboard monitor only; forwards events to the service.</summary>
    Helper
}

public sealed class RunContext
{
    public RunMode Mode { get; }
    public RunContext(RunMode mode) => Mode = mode;
}

public sealed class AgentWorker : BackgroundService
{
    private readonly AgentConfig _cfg;
    private readonly RunContext _ctx;

    public AgentWorker(AgentConfig cfg, RunContext ctx)
    {
        _cfg = cfg;
        _ctx = ctx;
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        var mode = _ctx.Mode;
        var disposables = new List<IDisposable>();
        UsbMonitor? usb = null;
        PrintMonitor? print = null;

        try
        {
            var policy = new PolicyStore(_cfg.PolicyCachePath, Path.Combine(AppContext.BaseDirectory, "policy.default.json"));
            policy.LoadFromDisk();
            var scanner = new ContentScanner(policy);

            if (mode == RunMode.Helper)
            {
                await RunHelperAsync(policy, scanner, disposables, ct);
                return;
            }

            Directory.CreateDirectory(_cfg.LogDirectory);
            var prefix = mode == RunMode.Console ? "events-console" : "events-service";
            var key = _cfg.DeriveLogKey();
            var secure = new SecureLog(_cfg.LogDirectory, prefix, key);
            var logger = new CompositeAlertLogger(new ConsoleAlertLogger(), new FileAlertLogger(secure));

            logger.Info("AGENT", $"Started agent={_cfg.AgentId} mode={mode} policyVersion={policy.Current.Version}");
            logger.Warn("VALIDATION_STATUS", "Experimental MVP: Windows/.NET build and endpoint behavior have not yet been validated by maintainers. Use only on an authorized, non-critical test device.");
            logger.Info("AGENT", $"Paths={string.Join(" | ", _cfg.SensitivePaths)}");

            // Telemetry + policy sync
            if (_cfg.TelemetryEnabled && _cfg.ServerUrl.Length > 0 && _cfg.ApiToken.Length > 0)
            {
                var client = new ServerClient(_cfg);
                disposables.Add(client);
                var outbox = new DiskOutbox(_cfg.LogDirectory, prefix, key);
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

            // Watchdog heartbeat + log retention
            var heartbeat = Path.Combine(_cfg.LogDirectory, "agent.heartbeat");
            _ = Task.Run(() => HeartbeatLoop(heartbeat, ct), ct);
            _ = Task.Run(() => RetentionLoop(_cfg.LogDirectory, _cfg.LogRetentionDays, ct), ct);

            // Detectors / monitors
            var rapid = new RapidActionDetector(logger, _cfg.RapidWindowSeconds, _cfg.RapidThreshold);
            var files = new FileMonitor(_cfg.SensitivePaths, new MagicBytesChecker(), rapid, new EntropyAnalyzer(),
                scanner, logger, _cfg.HighEntropyThreshold, _cfg.MaxScanBytes, _cfg.LogDirectory);
            disposables.Add(files);
            files.Start();

            usb = new UsbMonitor(logger, policy, files);
            usb.Start();

            print = new PrintMonitor(logger, policy);
            print.Start();

            if (mode == RunMode.Service)
            {
                var pipe = new HelperPipeServer(logger);
                _ = Task.Run(() => pipe.RunAsync(ct), ct);
            }
            else
            {
                var clip = new ClipboardMonitor(logger, policy, scanner);
                disposables.Add(clip);
                clip.Start();
                var watermark = new ScreenWatermark(policy, logger);
                disposables.Add(watermark);
                watermark.Start();
            }

            try { await Task.Delay(Timeout.Infinite, ct); }
            catch (OperationCanceledException) { }

            logger.Info("AGENT", "Stopping");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Fatal: {ex}");
            throw;
        }
        finally
        {
            usb?.Stop();
            print?.Stop();
            foreach (var d in disposables)
            {
                try { d.Dispose(); } catch { }
            }
        }
    }

    private async Task RunHelperAsync(PolicyStore policy, ContentScanner scanner, List<IDisposable> disposables, CancellationToken ct)
    {
        var pipe = new PipeAlertLogger();
        disposables.Add(pipe);
        var logger = new CompositeAlertLogger(new ConsoleAlertLogger(), pipe);

        var clip = new ClipboardMonitor(logger, policy, scanner);
        disposables.Add(clip);
        clip.Start();
        var watermark = new ScreenWatermark(policy, logger);
        disposables.Add(watermark);
        watermark.Start();
        logger.Info("HELPER", "User-session helper started");

        // The helper cannot verify signatures (it has no token); it trusts the ACL-protected cache the service writes.
        while (!ct.IsCancellationRequested)
        {
            policy.ReloadIfChanged();
            try { await Task.Delay(TimeSpan.FromSeconds(30), ct); } catch (OperationCanceledException) { break; }
        }
    }

    private static async Task HeartbeatLoop(string path, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try { await File.WriteAllTextAsync(path, DateTime.UtcNow.ToString("o"), ct); }
            catch (OperationCanceledException) { break; }
            catch { /* ignore */ }

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
