// OpenDLP Agent - GPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace OpenDLP.Agent;

public interface IAlertLogger
{
    void Info(string eventType, string message);
    void Warn(string eventType, string message);
    void Alert(string eventType, string message);
}

public sealed class ConsoleAlertLogger : IAlertLogger
{
    private readonly object _lock = new();
    public void Info(string t, string m) => Write(t, m, ConsoleColor.Gray);
    public void Warn(string t, string m) => Write(t, m, ConsoleColor.Yellow);
    public void Alert(string t, string m) => Write(t, m, ConsoleColor.Red);

    private void Write(string eventType, string message, ConsoleColor color)
    {
        try
        {
            lock (_lock)
            {
                var old = Console.ForegroundColor;
                Console.ForegroundColor = color;
                Console.WriteLine($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [{eventType}] {message}");
                Console.ForegroundColor = old;
            }
        }
        catch { /* no console attached (service) */ }
    }
}

public sealed class FileAlertLogger : IAlertLogger
{
    private readonly SecureLog _log;
    public FileAlertLogger(SecureLog log) => _log = log;
    public void Info(string t, string m) => _log.Append("INFO", t, m);
    public void Warn(string t, string m) => _log.Append("WARN", t, m);
    public void Alert(string t, string m) => _log.Append("ALERT", t, m);
}

public sealed class CompositeAlertLogger : IAlertLogger
{
    private readonly IAlertLogger[] _loggers;
    public CompositeAlertLogger(params IAlertLogger[] loggers) => _loggers = loggers;
    public void Info(string t, string m) { foreach (var l in _loggers) l.Info(t, m); }
    public void Warn(string t, string m) { foreach (var l in _loggers) l.Warn(t, m); }
    public void Alert(string t, string m) { foreach (var l in _loggers) l.Alert(t, m); }
}

/// <summary>
/// Encrypted, tamper-evident (AES-GCM) append-only event log: one base64 line per event.
/// This file is also the durable upload queue (see <see cref="DiskOutbox"/>).
/// </summary>
public sealed class SecureLog
{
    private const int NonceSize = 12;
    private const int TagSize = 16;

    private readonly string _dir;
    private readonly string _prefix;
    private readonly byte[] _key;
    private readonly object _lock = new();

    public SecureLog(string directory, string prefix, byte[] key)
    {
        _dir = directory;
        _prefix = prefix;
        _key = key;
        Directory.CreateDirectory(_dir);
    }

    public void Append(string level, string eventType, string message)
    {
        if (message.Length > 8000) message = message[..8000];

        var record = new Dictionary<string, object?>
        {
            ["ts"] = DateTime.UtcNow.ToString("o"),
            ["level"] = level,
            ["eventType"] = eventType,
            ["message"] = message,
            ["host"] = Environment.MachineName
        };

        var line = Convert.ToBase64String(Encrypt(JsonSerializer.Serialize(record), _key));
        var file = Path.Combine(_dir, $"{_prefix}-{DateTime.UtcNow:yyyyMMdd}.log");

        lock (_lock)
        {
            File.AppendAllText(file, line + "\n");
        }
    }

    // Format: nonce(12) | tag(16) | ciphertext
    private static byte[] Encrypt(string plain, byte[] key)
    {
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var data = Encoding.UTF8.GetBytes(plain);
        var cipher = new byte[data.Length];
        var tag = new byte[TagSize];

        using var gcm = new AesGcm(key, TagSize);
        gcm.Encrypt(nonce, data, cipher, tag);

        var output = new byte[NonceSize + TagSize + cipher.Length];
        Buffer.BlockCopy(nonce, 0, output, 0, NonceSize);
        Buffer.BlockCopy(tag, 0, output, NonceSize, TagSize);
        Buffer.BlockCopy(cipher, 0, output, NonceSize + TagSize, cipher.Length);
        return output;
    }

    public static string Decrypt(string base64Line, byte[] key)
    {
        var raw = Convert.FromBase64String(base64Line.Trim());
        var nonce = raw.AsSpan(0, NonceSize);
        var tag = raw.AsSpan(NonceSize, TagSize);
        var cipher = raw.AsSpan(NonceSize + TagSize);
        var plain = new byte[cipher.Length];

        using var gcm = new AesGcm(key, TagSize);
        gcm.Decrypt(nonce, cipher, tag, plain);
        return Encoding.UTF8.GetString(plain);
    }

    /// <summary>Delete log files older than the retention period.</summary>
    public static void Purge(string directory, int retentionDays)
    {
        try
        {
            var cutoff = DateTime.UtcNow.AddDays(-retentionDays);
            foreach (var f in Directory.GetFiles(directory, "events-*.log"))
            {
                try { if (File.GetLastWriteTimeUtc(f) < cutoff) File.Delete(f); } catch { }
            }
        }
        catch { /* ignore */ }
    }
}

public sealed class OutboxCursor
{
    public string File { get; set; } = "";
    public long Offset { get; set; }
}

/// <summary>
/// Durable at-least-once upload queue. Reads the encrypted log files in order and remembers how far
/// it got in a small cursor file, so a crash or reboot never loses un-uploaded events.
/// </summary>
public sealed class DiskOutbox
{
    private readonly string _dir;
    private readonly string _prefix;
    private readonly byte[] _key;
    private readonly string _cursorPath;

    public DiskOutbox(string directory, string prefix, byte[] key)
    {
        _dir = directory;
        _prefix = prefix;
        _key = key;
        _cursorPath = Path.Combine(directory, $"{prefix}.cursor");
    }

    private OutboxCursor? LoadCursor()
    {
        try
        {
            if (!File.Exists(_cursorPath)) return null;
            return JsonSerializer.Deserialize<OutboxCursor>(File.ReadAllText(_cursorPath));
        }
        catch { return null; }
    }

    public void Commit(OutboxCursor cursor)
    {
        try
        {
            var tmp = _cursorPath + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(cursor));
            File.Move(tmp, _cursorPath, overwrite: true);
        }
        catch { /* worst case: some events are re-sent (at-least-once) */ }
    }

    public (List<string> Events, OutboxCursor Next) ReadBatch(int max)
    {
        var cur = LoadCursor();
        var events = new List<string>();
        var files = Directory.GetFiles(_dir, $"{_prefix}-*.log")
            .OrderBy(f => Path.GetFileName(f), StringComparer.Ordinal)
            .ToList();

        if (files.Count == 0) return (events, cur ?? new OutboxCursor());

        var idx = 0;
        long offset = 0;
        if (cur != null && cur.File.Length > 0)
        {
            idx = files.FindIndex(f => string.Equals(Path.GetFileName(f), cur.File, StringComparison.OrdinalIgnoreCase));
            offset = cur.Offset;
            if (idx < 0)
            {
                // cursor file was purged: continue with the first file that sorts after it
                idx = files.FindIndex(f => string.CompareOrdinal(Path.GetFileName(f), cur.File) > 0);
                offset = 0;
                if (idx < 0) return (events, cur);
            }
        }

        var linesTotal = 0;
        while (idx < files.Count && linesTotal < max)
        {
            var (lines, newOffset) = ReadLines(files[idx], offset, max - linesTotal);
            offset = newOffset;
            linesTotal += lines.Count;

            foreach (var l in lines)
            {
                try { events.Add(SecureLog.Decrypt(l, _key)); }
                catch { /* corrupted or tampered line: skip it */ }
            }

            if (linesTotal >= max) break;

            // This file has no more complete lines. If a newer file exists, this one is finished.
            if (idx < files.Count - 1) { idx++; offset = 0; }
            else break;
        }

        return (events, new OutboxCursor { File = Path.GetFileName(files[idx]), Offset = offset });
    }

    private static (List<string> Lines, long NewOffset) ReadLines(string path, long offset, int maxLines)
    {
        var lines = new List<string>();
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (offset > fs.Length) offset = fs.Length; // file was truncated
            fs.Seek(offset, SeekOrigin.Begin);

            var buf = new byte[256 * 1024];
            var read = fs.Read(buf, 0, buf.Length);
            var text = Encoding.ASCII.GetString(buf, 0, read);

            var pos = 0;
            while (lines.Count < maxLines)
            {
                var nl = text.IndexOf('\n', pos);
                if (nl < 0) break; // partial line still being written
                lines.Add(text.Substring(pos, nl - pos).TrimEnd('\r'));
                offset += (nl - pos) + 1;
                pos = nl + 1;
            }
        }
        catch { /* file locked or vanished */ }
        return (lines, offset);
    }
}
