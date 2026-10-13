// OpenDLP Agent - GPL-3.0-only (shared by the Windows and macOS agents)
using System.Collections.Concurrent;

namespace OpenDLP.Agent;

public sealed class FileMonitor : IDisposable
{
    private readonly IReadOnlyList<string> _paths;
    private readonly ConcurrentDictionary<string, FileSystemWatcher> _watchers = new(StringComparer.OrdinalIgnoreCase);
    private readonly MagicBytesChecker _magic;
    private readonly RapidActionDetector _rapid;
    private readonly EntropyAnalyzer _entropy;
    private readonly ContentScanner _scanner;
    private readonly IAlertLogger _logger;
    private readonly double _entropyThreshold;
    private readonly int _maxScanBytes;
    private readonly string _logDir;
    private readonly ConcurrentDictionary<string, DateTime> _dedup = new();
    private readonly ConcurrentDictionary<string, DateTime> _lastScan = new();
    private readonly SemaphoreSlim _scanGate = new(2);

    public FileMonitor(
        IEnumerable<string> paths,
        MagicBytesChecker magic,
        RapidActionDetector rapid,
        EntropyAnalyzer entropy,
        ContentScanner scanner,
        IAlertLogger logger,
        double entropyThreshold,
        int maxScanBytes,
        string logDirectory)
    {
        _paths = paths.ToList();
        _magic = magic;
        _rapid = rapid;
        _entropy = entropy;
        _scanner = scanner;
        _logger = logger;
        _entropyThreshold = entropyThreshold;
        _maxScanBytes = maxScanBytes;
        _logDir = logDirectory;
    }

    public void Start()
    {
        foreach (var p in _paths) AddWatcher(p, usb: false);
        _logger.Info("FILE_MONITOR", $"Watching {_watchers.Count} path(s)");
    }

    public void WatchRemovable(string root) => AddWatcher(root, usb: true);

    public void UnwatchRemovable(string root)
    {
        if (_watchers.TryRemove(root, out var w))
        {
            try { w.EnableRaisingEvents = false; w.Dispose(); } catch { }
        }
    }

    private void AddWatcher(string path, bool usb)
    {
        try
        {
            var w = new FileSystemWatcher(path)
            {
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.CreationTime,
                IncludeSubdirectories = true,
                InternalBufferSize = 64 * 1024
            };
            w.Created += (_, e) => OnFsEvent(e.FullPath, e.ChangeType.ToString(), usb);
            w.Changed += (_, e) => OnFsEvent(e.FullPath, e.ChangeType.ToString(), usb);
            w.Renamed += (_, e) => OnRenamed(e, usb);
            w.Error += (_, e) => _logger.Alert("FILE_WATCHER", $"severity=medium {path}: {e.GetException().Message}");
            w.EnableRaisingEvents = true;
            _watchers[path] = w;
        }
        catch (Exception ex)
        {
            _logger.Warn("FILE_WATCHER", $"Cannot watch {path}: {ex.Message}");
        }
    }

    public void Dispose()
    {
        foreach (var w in _watchers.Values)
        {
            try { w.EnableRaisingEvents = false; w.Dispose(); } catch { }
        }
        _watchers.Clear();
    }

    private bool ShouldIgnore(string path)
    {
        var name = Path.GetFileName(path);
        if (name.StartsWith("~$", StringComparison.Ordinal)) return true;
        var ext = Path.GetExtension(path);
        if (ext is ".tmp" or ".crdownload" or ".part") return true;
        return _logDir.Length > 0 && path.StartsWith(_logDir, StringComparison.OrdinalIgnoreCase);
    }

    private void OnFsEvent(string path, string changeType, bool usb)
    {
        if (Directory.Exists(path)) return;
        if (ShouldIgnore(path)) return;
        if (IsDup(path)) return;
        _rapid.Touch();
        _ = Task.Run(() => AnalyzeAsync(path, changeType, usb));
    }

    private void OnRenamed(RenamedEventArgs e, bool usb)
    {
        _rapid.Touch();
        _logger.Warn(usb ? "USB_FILE_RENAMED" : "FILE_RENAMED", $"{e.OldFullPath} -> {e.FullPath}");
        if (Directory.Exists(e.FullPath) || ShouldIgnore(e.FullPath)) return;
        _ = Task.Run(() => AnalyzeAsync(e.FullPath, "Renamed", usb));
    }

    private async Task AnalyzeAsync(string path, string changeType, bool usb)
    {
        try
        {
            await Task.Delay(150);
            var tag = usb ? "USB_FILE" : "FILE";
            var detected = _magic.DetectFileType(path);
            var ext = Path.GetExtension(path).ToLowerInvariant();
            var mismatch = _magic.IsExtensionMismatch(ext, detected);
            var ent = _entropy.Estimate(path);

            if (changeType != "Renamed")
            {
                var line = $"{path} | ext={ext}; header={detected}; entropy={ent:F2}";
                if (usb) _logger.Warn($"{tag}_{changeType.ToUpperInvariant()}", line);
                else _logger.Info($"{tag}_{changeType.ToUpperInvariant()}", line);
            }

            if (mismatch)
                _logger.Alert("EVASION_ALERT", $"severity=high Extension/header mismatch: {path}");

            if (ent >= _entropyThreshold)
                _logger.Alert("HIGH_ENTROPY", $"severity=medium High entropy file: {path} ({ent:F2})");

            CheckFingerprints(path, usb);

            if (TextExtractor.IsSupported(path))
                await ScanContentAsync(path, usb);
        }
        catch (Exception ex)
        {
            _logger.Warn("FILE_ANALYZE_ERROR", ex.Message);
        }
    }

    private async Task ScanContentAsync(string path, bool usb)
    {
        var now = DateTime.UtcNow;
        if (_lastScan.TryGetValue(path, out var last) && (now - last).TotalSeconds < 60) return;
        _lastScan[path] = now;
        if (_lastScan.Count > 5000)
            foreach (var kv in _lastScan)
                if ((now - kv.Value).TotalMinutes > 5) _lastScan.TryRemove(kv.Key, out _);

        await _scanGate.WaitAsync();
        try
        {
            var text = TextExtractor.Extract(path, _maxScanBytes);
            if (text == null) return;

            var hits = _scanner.Scan(text);
            if (hits.Count == 0)
            {
                await ClassifyWithAiAsync(path, text, usb);
                return;
            }

            var type = usb ? "USB_FILE_CONTENT" : "CONTENT_MATCH";
            var msg = $"{ContentScanner.Summarize(hits)} file={path}";
            if (hits.Any(h => h.Action is "alert" or "block")) _logger.Alert(type, msg);
            else _logger.Info(type, msg);
        }
        finally
        {
            _scanGate.Release();
        }
    }

    /// <summary>Exact copies of registered confidential files (also inside .zip), regardless of file name.</summary>
    private void CheckFingerprints(string path, bool usb)
    {
        var fps = _scanner.Policy.Current.Fingerprints;
        if (fps.Count == 0) return;
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var f in fps)
            if (!string.IsNullOrWhiteSpace(f.Sha256)) map.TryAdd(f.Sha256.Trim(), f.Name);
        try
        {
            foreach (var (name, sha) in TextExtractor.Hashes(path))
            {
                if (!map.TryGetValue(sha, out var fpName)) continue;
                var entry = name == Path.GetFileName(path) ? "" : $" entry={name}";
                _logger.Alert(usb ? "USB_FINGERPRINT_MATCH" : "FINGERPRINT_MATCH",
                    $"severity=critical rules=FINGERPRINTx1 fingerprint=\"{fpName}\" file={path}{entry}");
                return;
            }
        }
        catch (IOException) { /* locked / gone */ }
        catch (UnauthorizedAccessException) { }
    }

    private static readonly AiClassifier Ai = new();

    /// <summary>Optional: ask the organisation's own model to classify documents no rule matched.</summary>
    private async Task ClassifyWithAiAsync(string path, string text, bool usb)
    {
        var ai = _scanner.Policy.Current.Ai;
        if (!ai.Enabled || string.IsNullOrWhiteSpace(ai.Endpoint) || string.IsNullOrWhiteSpace(text)) return;
        var result = await Ai.ClassifyAsync(ai, text, CancellationToken.None);
        if (result == null || result.Value.Label != "confidential") return;
        var msg = $"severity=high rules=AI-CONFIDENTIALx1 model={ai.Model} reason=\"{result.Value.Reason}\" file={path}";
        var type = usb ? "USB_AI_CLASSIFIED" : "AI_CLASSIFIED";
        if (ai.Action.Equals("log", StringComparison.OrdinalIgnoreCase)) _logger.Info(type, msg);
        else _logger.Alert(type, msg);
    }

    private bool IsDup(string path)
    {
        var now = DateTime.UtcNow;
        if (_dedup.Count > 5000)
            foreach (var kv in _dedup)
                if ((now - kv.Value).TotalSeconds > 10) _dedup.TryRemove(kv.Key, out _);

        if (_dedup.TryGetValue(path, out var last) && (now - last).TotalMilliseconds < 300) return true;
        _dedup[path] = now;
        return false;
    }
}
