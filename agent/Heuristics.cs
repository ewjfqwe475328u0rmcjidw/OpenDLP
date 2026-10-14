// Leakwarden Agent - GPL-3.0-only
using System.Collections.Concurrent;

namespace Leakwarden.Agent;

public sealed class RapidActionDetector
{
    private readonly IAlertLogger _logger;
    private readonly int _windowSeconds;
    private readonly int _threshold;
    private readonly ConcurrentQueue<DateTime> _events = new();
    private DateTime _lastAlert = DateTime.MinValue;

    public RapidActionDetector(IAlertLogger logger, int windowSeconds, int threshold)
    {
        _logger = logger;
        _windowSeconds = windowSeconds;
        _threshold = threshold;
    }

    public void Touch()
    {
        var now = DateTime.UtcNow;
        _events.Enqueue(now);
        while (_events.TryPeek(out var t) && (now - t).TotalSeconds > _windowSeconds)
            _events.TryDequeue(out _);

        if (_events.Count >= _threshold && (now - _lastAlert).TotalSeconds > _windowSeconds)
        {
            _lastAlert = now;
            _logger.Alert("RAPID_ACTION", $"severity=medium High file activity: {_events.Count} events / {_windowSeconds}s");
        }
    }
}

public sealed class EntropyAnalyzer
{
    public double Estimate(string filePath, int sampleSize = 4096)
    {
        try
        {
            if (!File.Exists(filePath)) return 0;
            var buffer = new byte[sampleSize];
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var read = fs.Read(buffer, 0, buffer.Length);
            if (read <= 0) return 0;

            var freq = new int[256];
            for (var i = 0; i < read; i++) freq[buffer[i]]++;

            double entropy = 0;
            for (var i = 0; i < 256; i++)
            {
                if (freq[i] == 0) continue;
                var p = (double)freq[i] / read;
                entropy -= p * Math.Log2(p);
            }
            return entropy;
        }
        catch { return 0; }
    }
}

public sealed class MagicBytesChecker
{
    public string DetectFileType(string filePath)
    {
        try
        {
            if (!File.Exists(filePath)) return "FILE_NOT_FOUND";
            var buffer = new byte[8];
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var read = fs.Read(buffer, 0, buffer.Length);
            if (read < 4) return "UNKNOWN_SHORT_FILE";

            var hex = Convert.ToHexString(buffer, 0, read);
            if (hex.StartsWith("25504446", StringComparison.Ordinal)) return "PDF";
            if (hex.StartsWith("504B0304", StringComparison.Ordinal)) return "ZIP_OR_OOXML";
            if (hex.StartsWith("FFD8FF", StringComparison.Ordinal)) return "JPEG";
            if (hex.StartsWith("89504E47", StringComparison.Ordinal)) return "PNG";
            if (hex.StartsWith("4D5A", StringComparison.Ordinal)) return "PE_EXECUTABLE";
            if (hex.StartsWith("52617221", StringComparison.Ordinal)) return "RAR";
            return $"RAW({hex[..Math.Min(8, hex.Length)]})";
        }
        catch { return "ACCESS_DENIED_OR_LOCKED"; }
    }

    public bool IsExtensionMismatch(string extension, string detectedType) => extension switch
    {
        ".jpg" or ".jpeg" or ".png" => detectedType is "PDF" or "PE_EXECUTABLE" or "ZIP_OR_OOXML" or "RAR",
        ".txt" or ".log" or ".csv" => detectedType is "PE_EXECUTABLE" or "ZIP_OR_OOXML" or "PDF",
        ".doc" or ".docx" or ".xls" or ".xlsx" or ".ppt" or ".pptx" or ".pdf" => detectedType is "PE_EXECUTABLE",
        _ => false
    };
}
