// OpenDLP Agent - GPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace OpenDLP.Agent;

public sealed class AgentConfig
{
    public static string DefaultLogDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "OpenDLP", "logs");

    public static string DefaultPolicyPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "OpenDLP", "policy", "policy.json");

    public string AgentId { get; init; } = Environment.MachineName;
    public string[] SensitivePaths { get; init; } = Array.Empty<string>();
    public string LogDirectory { get; init; } = DefaultLogDir;
    public string PolicyCachePath { get; init; } = DefaultPolicyPath;
    public bool TelemetryEnabled { get; init; }
    public string ServerUrl { get; init; } = "";
    public string ApiToken { get; init; } = "";
    public int PolicyPollSeconds { get; init; } = 60;
    public int LogRetentionDays { get; init; } = 30;
    public int MaxScanBytes { get; init; } = 4_000_000;
    public int RapidWindowSeconds { get; init; } = 10;
    public int RapidThreshold { get; init; } = 30;
    public double HighEntropyThreshold { get; init; } = 7.5;
    /// <summary>PEM-encoded ECDSA P-256 public key. When set, policies must also carry a valid asymmetric signature.</summary>
    public string PolicySigningPublicKey { get; init; } = "";
    /// <summary>One-time enrollment code (OPENDLP_ENROLL_CODE on the server). Used only when no token is available.</summary>
    public string EnrollmentCode { get; init; } = "";
    public string CredentialPath { get; init; } = Enrollment.DefaultCredentialPath;
    public string DisplayName { get; init; } = "";

    /// <summary>Helper (user-session) mode never reads the secret config file.</summary>
    public static AgentConfig Defaults() => new();

    public static AgentConfig Load(string file)
    {
        if (!File.Exists(file))
            throw new FileNotFoundException("agent.config.json not found (copy agent.config.example.json)", file);

        using var doc = JsonDocument.Parse(File.ReadAllText(file));
        var root = doc.RootElement;

        string Str(string name, string def) =>
            root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? (v.GetString() ?? def) : def;
        int Int(string name, int def) =>
            root.TryGetProperty(name, out var v) && v.TryGetInt32(out var i) ? i : def;
        double Dbl(string name, double def) =>
            root.TryGetProperty(name, out var v) && v.TryGetDouble(out var d) ? d : def;
        bool Bool(string name, bool def) =>
            root.TryGetProperty(name, out var v) && (v.ValueKind == JsonValueKind.True || v.ValueKind == JsonValueKind.False)
                ? v.GetBoolean() : def;

        var paths = new List<string>();
        if (root.TryGetProperty("SensitivePaths", out var sp) && sp.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in sp.EnumerateArray())
            {
                var raw = item.GetString();
                if (string.IsNullOrWhiteSpace(raw)) continue;
                foreach (var p in ExpandPath(raw))
                    if (Directory.Exists(p)) paths.Add(p);
            }
        }

        var credentialPath = Environment.ExpandEnvironmentVariables(Str("CredentialPath", Enrollment.DefaultCredentialPath));
        var serverUrl = Str("ServerUrl", "");
        var agentId = Str("AgentId", Environment.MachineName);
        var enrollCode = Environment.GetEnvironmentVariable("OPENDLP_ENROLL_CODE");
        if (string.IsNullOrWhiteSpace(enrollCode)) enrollCode = Str("EnrollmentCode", "");

        // Token precedence: environment variable > config file > DPAPI credential store > self-enrollment.
        var token = Environment.GetEnvironmentVariable("OPENDLP_TOKEN");
        if (string.IsNullOrWhiteSpace(token)) token = Str("ApiToken", "");
        if (string.IsNullOrWhiteSpace(token)) token = Enrollment.LoadToken(credentialPath);
        if (string.IsNullOrWhiteSpace(token) && !string.IsNullOrWhiteSpace(enrollCode) && serverUrl.Length > 0)
        {
            token = Enrollment.Enroll(serverUrl, agentId, enrollCode.Trim(), Str("DisplayName", ""), m => Console.WriteLine($"[ENROLL] {m}"));
            if (!string.IsNullOrEmpty(token))
            {
                try { Enrollment.SaveToken(credentialPath, token); }
                catch (Exception ex) { Console.Error.WriteLine($"[ENROLL] Could not persist token: {ex.Message}"); }
            }
        }

        return new AgentConfig
        {
            AgentId = agentId,
            SensitivePaths = paths.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
            LogDirectory = Environment.ExpandEnvironmentVariables(Str("LogDirectory", DefaultLogDir)),
            PolicyCachePath = Environment.ExpandEnvironmentVariables(Str("PolicyCachePath", DefaultPolicyPath)),
            TelemetryEnabled = Bool("TelemetryEnabled", false),
            ServerUrl = serverUrl,
            ApiToken = token ?? "",
            PolicyPollSeconds = Math.Max(15, Int("PolicyPollSeconds", 60)),
            LogRetentionDays = Math.Max(1, Int("LogRetentionDays", 30)),
            MaxScanBytes = Math.Max(10_000, Int("MaxScanBytes", 4_000_000)),
            RapidWindowSeconds = Int("RapidWindowSeconds", 10),
            RapidThreshold = Int("RapidThreshold", 30),
            HighEntropyThreshold = Dbl("HighEntropyThreshold", 7.5),
            PolicySigningPublicKey = Str("PolicySigningPublicKey", "").Trim(),
            EnrollmentCode = enrollCode?.Trim() ?? "",
            CredentialPath = credentialPath,
            DisplayName = Str("DisplayName", "")
        };
    }

    /// <summary>
    /// Expands env vars and the {AllUsers} token (every profile under C:\Users).
    /// A service running as SYSTEM has no "current user", so %USERPROFILE% would point at the wrong place.
    /// </summary>
    private static IEnumerable<string> ExpandPath(string raw)
    {
        var s = Environment.ExpandEnvironmentVariables(raw);
        const string token = "{AllUsers}";
        if (!s.Contains(token, StringComparison.OrdinalIgnoreCase))
        {
            yield return s;
            yield break;
        }

        var usersRoot = Path.Combine(Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\", "Users");
        if (!Directory.Exists(usersRoot)) yield break;

        foreach (var dir in Directory.GetDirectories(usersRoot))
        {
            var name = Path.GetFileName(dir);
            if (name is "Public" or "Default" or "Default User" or "All Users") continue;
            yield return s.Replace(token, dir, StringComparison.OrdinalIgnoreCase);
        }
    }

    // Demo-grade: derive the local-log key from AgentId + token. Production: DPAPI machine scope / KMS.
    public byte[] DeriveLogKey()
    {
        var material = $"{AgentId}|{ApiToken}|OpenDLP-Log-Key-v1";
        return SHA256.HashData(Encoding.UTF8.GetBytes(material));
    }

    /// <summary>Key used to verify server policy signatures (hex of SHA-256(token), as UTF-8 bytes).</summary>
    public byte[] PolicyVerifyKey()
    {
        var hex = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(ApiToken))).ToLowerInvariant();
        return Encoding.UTF8.GetBytes(hex);
    }
}
