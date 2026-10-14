// Leakwarden Agent (macOS / Linux) - GPL-3.0-only
namespace Leakwarden.Agent;

/// <summary>
/// Removable-volume auditing: polls the mount roots (/Volumes on macOS; /media, /run/media on Linux),
/// logs USB_INSERT / USB_REMOVE and adds new volumes to the file monitor so copies onto them are inspected.
/// Audit only: USB "block" mode is not implemented on macOS/Linux.
/// </summary>
public sealed class VolumeMonitor
{
    private readonly IAlertLogger _logger;
    private readonly PolicyStore _policy;
    private readonly FileMonitor _files;
    private readonly HashSet<string> _known = new(StringComparer.Ordinal);
    private bool _blockWarned;

    public VolumeMonitor(IAlertLogger logger, PolicyStore policy, FileMonitor files)
    {
        _logger = logger;
        _policy = policy;
        _files = files;
    }

    public static IEnumerable<string> CurrentVolumes()
    {
        var roots = OperatingSystem.IsMacOS() ? new[] { "/Volumes" } : new[] { "/media", "/run/media" };
        foreach (var root in roots)
        {
            if (!Directory.Exists(root)) continue;
            IEnumerable<string> dirs;
            try { dirs = Directory.GetDirectories(root); } catch { continue; }
            foreach (var d in dirs)
            {
                // macOS: "/Volumes/Macintosh HD" is a symlink to "/" (the boot volume) - skip symlinks.
                FileSystemInfo info = new DirectoryInfo(d);
                if (info.LinkTarget != null) continue;
                // Linux: /media/<user>/<volume> and /run/media/<user>/<volume>
                if (!OperatingSystem.IsMacOS())
                {
                    string[] sub;
                    try { sub = Directory.GetDirectories(d); } catch { continue; }
                    foreach (var s in sub) yield return s;
                    continue;
                }
                yield return d;
            }
        }
    }

    public async Task RunAsync(CancellationToken ct)
    {
        foreach (var v in CurrentVolumes()) _known.Add(v);   // volumes present at start are not "inserted"
        foreach (var v in _known) _files.WatchRemovable(v);
        _logger.Info("USB_MONITOR", $"Volume monitor started ({_known.Count} mounted)");

        while (!ct.IsCancellationRequested)
        {
            try
            {
                var now = CurrentVolumes().ToHashSet(StringComparer.Ordinal);
                foreach (var added in now.Except(_known).ToList())
                {
                    _known.Add(added);
                    _logger.Warn("USB_INSERT", $"Volume mounted: {added}");
                    if (_policy.Current.Usb.Mode.Equals("block", StringComparison.OrdinalIgnoreCase) && !_blockWarned)
                    {
                        _blockWarned = true;
                        _logger.Warn("USB_MONITOR", "USB block mode is not supported on this OS yet; auditing only");
                    }
                    _files.WatchRemovable(added);
                }
                foreach (var removed in _known.Except(now).ToList())
                {
                    _known.Remove(removed);
                    _files.UnwatchRemovable(removed);
                    _logger.Warn("USB_REMOVE", $"Volume removed: {removed}");
                }
            }
            catch (Exception ex)
            {
                _logger.Warn("USB_MONITOR", ex.Message);
            }
            try { await Task.Delay(3000, ct); } catch (OperationCanceledException) { break; }
        }
    }
}
