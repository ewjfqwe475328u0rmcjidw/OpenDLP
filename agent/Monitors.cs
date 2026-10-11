// OpenDLP Agent - GPL-3.0-only
using System.Collections.Concurrent;
using System.Management;

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
            if (hits.Count == 0) return;

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

public sealed class UsbMonitor
{
    private ManagementEventWatcher? _insert;
    private ManagementEventWatcher? _remove;
    private readonly IAlertLogger _logger;
    private readonly PolicyStore _policy;
    private readonly FileMonitor _files;

    public UsbMonitor(IAlertLogger logger, PolicyStore policy, FileMonitor files)
    {
        _logger = logger;
        _policy = policy;
        _files = files;
    }

    public void Start()
    {
        try
        {
            // DriveType 2 = removable; 3 = fixed (external USB HDDs report as fixed, so we check the bus below)
            _insert = Create(
                "SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_LogicalDisk' AND (TargetInstance.DriveType = 2 OR TargetInstance.DriveType = 3)",
                e =>
                {
                    var t = (ManagementBaseObject)e.NewEvent["TargetInstance"];
                    var drive = t["DeviceID"]?.ToString() ?? "";
                    var label = t["VolumeName"]?.ToString() ?? "NoLabel";
                    var driveType = Convert.ToInt32(t["DriveType"] ?? 0);
                    _ = Task.Run(() => HandleInsertAsync(drive, label, driveType));
                });

            _remove = Create(
                "SELECT * FROM __InstanceDeletionEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_LogicalDisk' AND (TargetInstance.DriveType = 2 OR TargetInstance.DriveType = 3)",
                e =>
                {
                    var t = (ManagementBaseObject)e.NewEvent["TargetInstance"];
                    var drive = t["DeviceID"]?.ToString() ?? "";
                    _files.UnwatchRemovable(drive + "\\");
                    _logger.Warn("USB_REMOVE", $"Drive removed: {drive}");
                });

            _insert.Start();
            _remove.Start();
            _logger.Info("USB_MONITOR", "USB monitor started");
        }
        catch (Exception ex)
        {
            _logger.Alert("USB_MONITOR", $"severity=medium Failed to start (admin/SYSTEM required): {ex.Message}");
        }
    }

    public void Stop()
    {
        try { _insert?.Stop(); _remove?.Stop(); } catch { }
        _insert?.Dispose();
        _remove?.Dispose();
    }

    private async Task HandleInsertAsync(string drive, string label, int driveType)
    {
        try
        {
            // The disk <-> partition association can lag behind the insert event
            UsbInfo info = default;
            for (var i = 0; i < 4; i++)
            {
                info = GetUsbInfo(drive);
                if (info.Serial.Length > 0) break;
                await Task.Delay(500);
            }

            if (driveType == 3 && !info.IsUsb) return; // internal / virtual fixed disk

            var usb = _policy.Current.Usb;
            var allowed = usb.AllowSerials.Any(s => string.Equals(s, info.Serial, StringComparison.OrdinalIgnoreCase));
            var detail = $"{drive} label={label} serial={info.Serial} model={info.Model} allowed={allowed}";

            if (!allowed && string.Equals(usb.Mode, "block", StringComparison.OrdinalIgnoreCase))
            {
                if (TryDismount(drive)) _logger.Alert("USB_BLOCKED", $"severity=high Dismounted unauthorized device: {detail}");
                else _logger.Alert("USB_BLOCK_FAILED", $"severity=high Could not dismount unauthorized device: {detail}");
                return;
            }

            _logger.Warn("USB_INSERT", detail);
            _files.WatchRemovable(drive + "\\");
        }
        catch (Exception ex)
        {
            _logger.Warn("USB_MONITOR", $"Insert handling failed: {ex.Message}");
        }
    }

    private readonly record struct UsbInfo(bool IsUsb, string Serial, string Model);

    private static UsbInfo GetUsbInfo(string drive)
    {
        try
        {
            using var parts = new ManagementObjectSearcher(
                $"ASSOCIATORS OF {{Win32_LogicalDisk.DeviceID='{drive}'}} WHERE AssocClass = Win32_LogicalDiskToPartition");
            foreach (ManagementObject part in parts.Get())
            {
                var partId = part["DeviceID"]?.ToString() ?? "";
                using var disks = new ManagementObjectSearcher(
                    $"ASSOCIATORS OF {{Win32_DiskPartition.DeviceID='{partId}'}} WHERE AssocClass = Win32_DiskDriveToDiskPartition");
                foreach (ManagementObject disk in disks.Get())
                {
                    var pnp = disk["PNPDeviceID"]?.ToString() ?? "";
                    var iface = disk["InterfaceType"]?.ToString() ?? "";
                    var model = disk["Model"]?.ToString() ?? "";
                    var isUsb = iface.Equals("USB", StringComparison.OrdinalIgnoreCase) ||
                                pnp.StartsWith("USBSTOR", StringComparison.OrdinalIgnoreCase);
                    return new UsbInfo(isUsb, ExtractSerial(pnp), model);
                }
            }
        }
        catch { /* WMI hiccup */ }
        return new UsbInfo(false, "", "");
    }

    // PNPDeviceID example: USBSTOR\DISK&VEN_SANDISK&PROD_ULTRA&REV_1.00\4C530001234567890123&0
    private static string ExtractSerial(string pnp)
    {
        var inst = pnp.Split('\\').LastOrDefault() ?? "";
        var amp = inst.IndexOf('&');
        return amp > 0 ? inst[..amp] : inst;
    }

    // Soft enforcement: dismount the volume so it is inaccessible until re-plugged. An admin can bypass this.
    private static bool TryDismount(string drive)
    {
        try
        {
            using var s = new ManagementObjectSearcher($"SELECT * FROM Win32_Volume WHERE DriveLetter = '{drive}'");
            foreach (ManagementObject v in s.Get())
            {
                var rc = v.InvokeMethod("Dismount", new object[] { true, false });
                return Convert.ToInt32(rc) == 0;
            }
        }
        catch { }
        return false;
    }

    private static ManagementEventWatcher Create(string query, EventArrivedEventHandler handler)
    {
        var w = new ManagementEventWatcher(new WqlEventQuery(query));
        w.EventArrived += handler;
        return w;
    }
}

public sealed class PrintMonitor
{
    private ManagementEventWatcher? _watcher;
    private readonly IAlertLogger _logger;
    private readonly PolicyStore _policy;

    public PrintMonitor(IAlertLogger logger, PolicyStore policy)
    {
        _logger = logger;
        _policy = policy;
    }

    public void Start()
    {
        try
        {
            // Polled every 2s, so very short jobs can be missed (documented limitation)
            _watcher = new ManagementEventWatcher(new WqlEventQuery(
                "SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_PrintJob'"));
            _watcher.EventArrived += (_, e) =>
            {
                if (!_policy.Current.Print.Enabled) return;
                var t = (ManagementBaseObject)e.NewEvent["TargetInstance"];
                _logger.Warn("PRINT_JOB",
                    $"printer/job={t["Name"]} owner={t["Owner"]} pages={t["TotalPages"]} doc={t["Document"]}");
            };
            _watcher.Start();
            _logger.Info("PRINT_MONITOR", "Print monitor started");
        }
        catch (Exception ex)
        {
            _logger.Warn("PRINT_MONITOR", $"Failed to start: {ex.Message}");
        }
    }

    public void Stop()
    {
        try { _watcher?.Stop(); } catch { }
        _watcher?.Dispose();
    }
}
