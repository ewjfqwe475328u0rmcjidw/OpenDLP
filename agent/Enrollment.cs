// Leakwarden Agent - GPL-3.0-only
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Leakwarden.Agent;

/// <summary>
/// Self-enrollment: exchange a one-time enrollment code for a per-machine token and keep it out of agent.config.json.
/// Windows: encrypted at rest with DPAPI (machine scope). macOS/Linux: a file readable only by root (mode 0600)
/// inside the root-owned data folder.
/// </summary>
public static class Enrollment
{
    public static string DefaultCredentialPath => Path.Combine(AgentConfig.DataRoot, "credentials.bin");

    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("Leakwarden-credentials-v1");

    public static string? LoadToken(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            var raw = File.ReadAllBytes(path);
            var plain = OperatingSystem.IsWindows()
                ? ProtectedData.Unprotect(raw, Entropy, DataProtectionScope.LocalMachine)
                : raw;
            var token = Encoding.UTF8.GetString(plain).Trim();
            return string.IsNullOrWhiteSpace(token) ? null : token;
        }
        catch
        {
            return null; // corrupted / moved between machines: fall through to re-enrollment
        }
    }

    public static void SaveToken(string path, string token)
    {
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        var tmp = path + ".tmp";
        if (OperatingSystem.IsWindows())
        {
            File.WriteAllBytes(tmp, ProtectedData.Protect(Encoding.UTF8.GetBytes(token), Entropy, DataProtectionScope.LocalMachine));
        }
        else
        {
            File.WriteAllBytes(tmp, Array.Empty<byte>());
            File.SetUnixFileMode(tmp, UnixFileMode.UserRead | UnixFileMode.UserWrite);   // 0600 before any secret is written
            File.WriteAllBytes(tmp, Encoding.UTF8.GetBytes(token));
        }
        File.Move(tmp, path, overwrite: true);
    }

    private sealed class EnrollResponse
    {
        public string AgentId { get; set; } = "";
        public string Token { get; set; } = "";
    }

    /// <summary>Blocking enrollment with a few retries; returns the issued token or null.</summary>
    public static string? Enroll(string serverUrl, string agentId, string enrollmentCode, string? displayName, Action<string> log)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
        http.DefaultRequestHeaders.TryAddWithoutValidation("X-Agent-Version", AgentVersion.Value);
        var url = serverUrl.TrimEnd('/') + "/api/v1/enroll";
        var body = new { agentId, enrollmentCode, host = Environment.MachineName, displayName };

        for (var attempt = 1; attempt <= 3; attempt++)
        {
            try
            {
                using var resp = http.PostAsJsonAsync(url, body).GetAwaiter().GetResult();
                if (resp.IsSuccessStatusCode)
                {
                    var r = resp.Content.ReadFromJsonAsync<EnrollResponse>(
                        new JsonSerializerOptions { PropertyNameCaseInsensitive = true }).GetAwaiter().GetResult();
                    if (r != null && !string.IsNullOrEmpty(r.Token))
                    {
                        log($"Enrolled with {serverUrl} as {agentId}");
                        return r.Token;
                    }
                    log("Enrollment response was empty");
                    return null;
                }
                if ((int)resp.StatusCode is 403 or 404 or 422 or 503)
                {
                    log($"Enrollment rejected: HTTP {(int)resp.StatusCode} (check the enrollment code / server configuration)");
                    return null; // not retryable
                }
                log($"Enrollment failed: HTTP {(int)resp.StatusCode}");
            }
            catch (Exception ex)
            {
                log($"Enrollment attempt {attempt} failed: {ex.Message}");
            }
            Thread.Sleep(TimeSpan.FromSeconds(3 * attempt));
        }
        return null;
    }
}
