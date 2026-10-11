// OpenDLP Agent - GPL-3.0-only
using System.Collections.Concurrent;
using System.Diagnostics.Eventing.Reader;
using System.Management;

namespace OpenDLP.Agent;


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
                (_, e) =>
                {
                    var t = (ManagementBaseObject)e.NewEvent["TargetInstance"];
                    var drive = t["DeviceID"]?.ToString() ?? "";
                    var label = t["VolumeName"]?.ToString() ?? "NoLabel";
                    var driveType = Convert.ToInt32(t["DriveType"] ?? 0);
                    _ = Task.Run(() => HandleInsertAsync(drive, label, driveType));
                });

            _remove = Create(
                "SELECT * FROM __InstanceDeletionEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_LogicalDisk' AND (TargetInstance.DriveType = 2 OR TargetInstance.DriveType = 3)",
                (_, e) =>
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

/// <summary>
/// Print auditing via the Windows PrintService operational event log (event 307 "document printed").
/// Unlike WMI polling of Win32_PrintJob this does not miss short jobs. The log is disabled by default;
/// the agent (running as SYSTEM) enables it on start.
/// </summary>
public sealed class PrintMonitor : IDisposable
{
    private const string LogName = "Microsoft-Windows-PrintService/Operational";
    private readonly IAlertLogger _logger;
    private readonly PolicyStore _policy;
    private EventLogWatcher? _watcher;

    public PrintMonitor(IAlertLogger logger, PolicyStore policy)
    {
        _logger = logger;
        _policy = policy;
    }

    public void Start()
    {
        try
        {
            EnsureLogEnabled();
            var query = new EventLogQuery(LogName, PathType.LogName, "*[System[(EventID=307)]]");
            _watcher = new EventLogWatcher(query);
            _watcher.EventRecordWritten += OnRecord;
            _watcher.Enabled = true;
            _logger.Info("PRINT_MONITOR", "Print monitor started (PrintService event log)");
        }
        catch (Exception ex)
        {
            _logger.Warn("PRINT_MONITOR", $"Failed to start: {ex.Message}");
        }
    }

    private void EnsureLogEnabled()
    {
        using var cfg = new EventLogConfiguration(LogName);
        if (cfg.IsEnabled) return;
        cfg.IsEnabled = true;
        cfg.SaveChanges();
        _logger.Info("PRINT_MONITOR", $"Enabled {LogName}");
    }

    private void OnRecord(object? sender, EventRecordWrittenEventArgs e)
    {
        try
        {
            using var rec = e.EventRecord;
            if (rec == null || !_policy.Current.Print.Enabled) return;
            var p = rec.Properties;
            string P(int i) => i < p.Count ? p[i].Value?.ToString() ?? "" : "";
            // Event 307 params: 1 job id, 2 document, 3 user, 4 client, 5 printer, 6 port, 7 bytes, 8 pages
            _logger.Warn("PRINT_JOB",
                $"printer={P(4)} user={P(2)} client={P(3)} pages={P(7)} bytes={P(6)} doc={P(1)}");
        }
        catch (Exception ex)
        {
            _logger.Warn("PRINT_MONITOR", $"Could not read print event: {ex.Message}");
        }
    }

    public void Stop()
    {
        try { if (_watcher != null) _watcher.Enabled = false; } catch { }
        _watcher?.Dispose();
        _watcher = null;
    }

    public void Dispose() => Stop();
}
