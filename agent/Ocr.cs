// OpenDLP Agent - GPL-3.0-only
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace OpenDLP.Agent;

/// <summary>Text recognition for images (screenshots, photos of ID cards, scanned documents), on the device only.</summary>
public sealed class OcrPolicy
{
    public bool Enabled { get; set; }
    /// <summary>Tesseract language codes joined with '+', e.g. "eng+chi_tra". Windows uses the installed OCR languages.</summary>
    public string Languages { get; set; } = "eng";
    public long MaxImageBytes { get; set; } = 20 * 1024 * 1024;
    /// <summary>Images recognised per minute at most (protects CPU when many screenshots are saved at once).</summary>
    public int MaxPerMinute { get; set; } = 30;
}

public static class Ocr
{
    public static readonly string[] ImageExtensions = { ".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff", ".gif", ".webp" };
    private static readonly Regex LangRx = new("^[A-Za-z_]{2,16}(\\+[A-Za-z_]{2,16}){0,7}$", RegexOptions.Compiled);

    /// <summary>Platform engine (Windows.Media.Ocr on Windows); returns null when unavailable. Tesseract is the fallback.</summary>
    public static Func<string, CancellationToken, Task<string?>>? PlatformEngine { get; set; }

    private static readonly object Gate = new();
    private static readonly Queue<DateTime> Recent = new();

    public static bool IsImage(string path) =>
        ImageExtensions.Contains(Path.GetExtension(path).ToLowerInvariant());

    public static bool TryAcquire(int maxPerMinute, DateTime? now = null)
    {
        var t = now ?? DateTime.UtcNow;
        lock (Gate)
        {
            while (Recent.Count > 0 && (t - Recent.Peek()).TotalSeconds >= 60) Recent.Dequeue();
            if (Recent.Count >= Math.Max(1, maxPerMinute)) return false;
            Recent.Enqueue(t);
            return true;
        }
    }

    public static void ResetRateLimit()
    {
        lock (Gate) Recent.Clear();
    }

    /// <summary>Recognised text, or null (disabled, too large, rate-limited or no OCR engine on this device).</summary>
    public static async Task<string?> RecognizeAsync(string path, OcrPolicy policy, CancellationToken ct)
    {
        if (!policy.Enabled || !IsImage(path)) return null;
        var info = new FileInfo(path);
        if (!info.Exists || info.Length == 0 || info.Length > policy.MaxImageBytes) return null;
        if (!TryAcquire(policy.MaxPerMinute)) return null;

        if (PlatformEngine != null)
        {
            try
            {
                var text = await PlatformEngine(path, ct);
                if (text != null) return text;
            }
            catch (Exception) { /* fall back to Tesseract */ }
        }
        return await TesseractAsync(path, policy.Languages, ct);
    }

    private static string? _tesseract;
    private static bool _searched;

    public static string? FindTesseract()
    {
        if (_searched) return _tesseract;
        var exe = OperatingSystem.IsWindows() ? "tesseract.exe" : "tesseract";
        var dirs = (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)
            .Concat(new[]
            {
                // Services (launchd/systemd/SCM) often run with a minimal PATH.
                "/usr/bin", "/usr/local/bin", "/opt/homebrew/bin", "/opt/local/bin",
                @"C:\Program Files\Tesseract-OCR", @"C:\Program Files (x86)\Tesseract-OCR",
            });
        _tesseract = dirs.Select(d => Path.Combine(d, exe)).FirstOrDefault(File.Exists);
        _searched = true;
        return _tesseract;
    }

    public static async Task<string?> TesseractAsync(string path, string languages, CancellationToken ct)
    {
        var exe = FindTesseract();
        if (exe == null) return null;
        var psi = new ProcessStartInfo(exe)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add(path);
        psi.ArgumentList.Add("stdout");
        psi.ArgumentList.Add("-l");
        psi.ArgumentList.Add(LangRx.IsMatch(languages ?? "") ? languages! : "eng");
        using var p = Process.Start(psi);
        if (p == null) return null;
        var stdout = p.StandardOutput.ReadToEndAsync(ct);
        _ = p.StandardError.ReadToEndAsync(ct);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));
        try
        {
            await p.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            try { p.Kill(entireProcessTree: true); } catch { /* already gone */ }
            return null;
        }
        return p.ExitCode == 0 ? await stdout : null;
    }
}
