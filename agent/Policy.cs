// OpenDLP Agent - GPL-3.0-only
using System.Text.Json;

namespace OpenDLP.Agent;

public sealed class PolicyDoc
{
    public long Version { get; set; }
    public List<ContentRule> Rules { get; set; } = new();
    public UsbPolicy Usb { get; set; } = new();
    public ClipboardPolicy Clipboard { get; set; } = new();
    public PrintPolicy Print { get; set; } = new();
    public BrowserPolicy Browser { get; set; } = new();
    /// <summary>Exact-match fingerprints of confidential files (added by the server from its registry).</summary>
    public List<Fingerprint> Fingerprints { get; set; } = new();
    public AiPolicy Ai { get; set; } = new();
    public OcrPolicy Ocr { get; set; } = new();
    public WatermarkPolicy Watermark { get; set; } = new();
}

/// <summary>Visible on-screen watermark (Windows): deters photographing or screen-sharing confidential data.</summary>
public sealed class WatermarkPolicy
{
    public bool Enabled { get; set; }
    /// <summary>Placeholders: {user} {host} {date} {time}</summary>
    public string Text { get; set; } = "{user} · {host} · {date}";
    public double Opacity { get; set; } = 0.08;
    public int FontSize { get; set; } = 16;
}

public sealed class Fingerprint
{
    public string Sha256 { get; set; } = "";
    public string Name { get; set; } = "";
}

/// <summary>Optional classification by a self-hosted model (Ollama-compatible). Off by default.</summary>
public sealed class AiPolicy
{
    public bool Enabled { get; set; }
    public string Endpoint { get; set; } = "";
    public string Model { get; set; } = "";
    public int MaxChars { get; set; } = 4000;
    /// <summary>log | alert</summary>
    public string Action { get; set; } = "alert";
}

public sealed class ContentRule
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    /// <summary>builtin | keywords | regex</summary>
    public string Type { get; set; } = "builtin";
    public string Detector { get; set; } = "";
    public string Pattern { get; set; } = "";
    public List<string> Keywords { get; set; } = new();
    public int MinMatches { get; set; } = 1;
    /// <summary>low | medium | high | critical</summary>
    public string Severity { get; set; } = "medium";
    /// <summary>log | alert | block</summary>
    public string Action { get; set; } = "alert";
    /// <summary>Builtin rules only: count a match only when a context word is near it (fewer false positives).</summary>
    public bool RequireContext { get; set; }
    /// <summary>Overrides the detector's default context words.</summary>
    public List<string> ContextWords { get; set; } = new();
    /// <summary>Regexes; a match that also matches one of these is ignored (e.g. documented example keys).</summary>
    public List<string> Exclude { get; set; } = new();
}

public sealed class UsbPolicy
{
    /// <summary>audit | block</summary>
    public string Mode { get; set; } = "audit";
    public List<string> AllowSerials { get; set; } = new();
}

public sealed class ClipboardPolicy
{
    public bool Enabled { get; set; } = true;
    /// <summary>log | alert | block</summary>
    public string Action { get; set; } = "alert";
}

public sealed class PrintPolicy
{
    public bool Enabled { get; set; } = true;
}

public sealed class BrowserPolicy
{
    /// <summary>audit | warn | block (used by the browser extension)</summary>
    public string Mode { get; set; } = "audit";
    public List<string> MonitoredDomains { get; set; } = new();
    public List<string> BlockedUploadDomains { get; set; } = new();
}

/// <summary>What the server sends: the policy as an exact JSON string plus an HMAC over that string.</summary>
public sealed class PolicyEnvelope
{
    public long Version { get; set; }
    public string PolicyJson { get; set; } = "";
    public string Sig { get; set; } = "";
    /// <summary>Optional ECDSA P-256 signature (base64 DER) over PolicyJson; verified when the agent is configured with the server public key.</summary>
    public string? PubSig { get; set; }
}

public sealed class PolicyStore
{
    private static readonly JsonSerializerOptions Opts = new() { PropertyNameCaseInsensitive = true };

    private readonly string _cachePath;
    private readonly string _defaultPath;
    private volatile PolicyDoc _current = new();
    private DateTime _cacheStamp = DateTime.MinValue;

    public PolicyStore(string cachePath, string defaultPath)
    {
        _cachePath = cachePath;
        _defaultPath = defaultPath;
    }

    public PolicyDoc Current => _current;

    /// <summary>Load the cached (server-supplied) policy, or fall back to the bundled default.</summary>
    public void LoadFromDisk()
    {
        try
        {
            if (File.Exists(_cachePath))
            {
                var env = JsonSerializer.Deserialize<PolicyEnvelope>(File.ReadAllText(_cachePath), Opts);
                if (env != null && !string.IsNullOrWhiteSpace(env.PolicyJson))
                {
                    var doc = JsonSerializer.Deserialize<PolicyDoc>(env.PolicyJson, Opts);
                    if (doc != null)
                    {
                        doc.Version = env.Version;
                        _current = doc;
                        _cacheStamp = File.GetLastWriteTimeUtc(_cachePath);
                        return;
                    }
                }
            }
        }
        catch { /* fall through to default */ }

        try
        {
            if (File.Exists(_defaultPath))
            {
                var doc = JsonSerializer.Deserialize<PolicyDoc>(File.ReadAllText(_defaultPath), Opts);
                if (doc != null) _current = doc;
            }
        }
        catch { /* keep empty policy */ }
    }

    /// <summary>Used by the user-session helper, which cannot verify signatures: re-read the cache when it changes.</summary>
    public void ReloadIfChanged()
    {
        try
        {
            if (!File.Exists(_cachePath)) return;
            var stamp = File.GetLastWriteTimeUtc(_cachePath);
            if (stamp != _cacheStamp) LoadFromDisk();
        }
        catch { /* ignore */ }
    }

    /// <summary>Apply an already-verified envelope and persist it.</summary>
    public bool Apply(PolicyEnvelope env)
    {
        try
        {
            var doc = JsonSerializer.Deserialize<PolicyDoc>(env.PolicyJson, Opts);
            if (doc == null) return false;
            doc.Version = env.Version;
            _current = doc;

            var dir = Path.GetDirectoryName(_cachePath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            var tmp = _cachePath + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(env));
            File.Move(tmp, _cachePath, overwrite: true);
            _cacheStamp = File.GetLastWriteTimeUtc(_cachePath);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
