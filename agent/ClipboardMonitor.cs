// Leakwarden Agent - GPL-3.0-only
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Leakwarden.Agent;

/// <summary>
/// Watches the clipboard for sensitive text. Must run inside the interactive user session (a Windows
/// service in session 0 has no access to the user's clipboard), hence the separate "helper" mode.
/// </summary>
public sealed class ClipboardMonitor : IDisposable
{
    [DllImport("user32.dll")] private static extern uint GetClipboardSequenceNumber();
    [DllImport("user32.dll")] private static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);

    private readonly IAlertLogger _logger;
    private readonly PolicyStore _policy;
    private readonly ContentScanner _scanner;
    private Thread? _thread;
    private volatile bool _stop;

    public ClipboardMonitor(IAlertLogger logger, PolicyStore policy, ContentScanner scanner)
    {
        _logger = logger;
        _policy = policy;
        _scanner = scanner;
    }

    public void Start()
    {
        _thread = new Thread(Loop) { IsBackground = true, Name = "Leakwarden.Clipboard" };
        _thread.SetApartmentState(ApartmentState.STA); // WinForms Clipboard requires STA
        _thread.Start();
        _logger.Info("CLIPBOARD_MONITOR", "Clipboard monitor started");
    }

    public void Dispose() => _stop = true;

    private void Loop()
    {
        var last = GetClipboardSequenceNumber();
        while (!_stop)
        {
            Thread.Sleep(700);
            try
            {
                var seq = GetClipboardSequenceNumber();
                if (seq == last) continue;
                HandleChange();
                last = GetClipboardSequenceNumber(); // Clear() bumps the sequence number; don't re-handle our own change
            }
            catch (Exception ex)
            {
                _logger.Warn("CLIPBOARD_ERROR", ex.Message);
                last = GetClipboardSequenceNumber();
            }
        }
    }

    private void HandleChange()
    {
        var pol = _policy.Current.Clipboard;
        if (!pol.Enabled) return;

        string? text = null;
        for (var i = 0; i < 3 && text == null; i++)
        {
            try
            {
                if (!Clipboard.ContainsText()) return;
                text = Clipboard.GetText();
            }
            catch (ExternalException) { Thread.Sleep(100); } // clipboard locked by another app
        }
        if (string.IsNullOrEmpty(text)) return;
        if (text.Length > 1_000_000) text = text[..1_000_000];

        var hits = _scanner.Scan(text);
        if (hits.Count == 0) return;

        var msg = $"{ContentScanner.Summarize(hits)} source_app={ForegroundProcessName()} length={text.Length}";
        var action = pol.Action.ToLowerInvariant();

        if (action == "block")
        {
            try { Clipboard.Clear(); } catch { /* owner may hold it */ }
            _logger.Alert("CLIPBOARD_BLOCKED", msg);
        }
        else if (action == "alert") _logger.Alert("CLIPBOARD_MATCH", msg);
        else _logger.Info("CLIPBOARD_MATCH", msg);
    }

    private static string ForegroundProcessName()
    {
        try
        {
            GetWindowThreadProcessId(GetForegroundWindow(), out var pid);
            return Process.GetProcessById((int)pid).ProcessName;
        }
        catch { return "unknown"; }
    }
}
