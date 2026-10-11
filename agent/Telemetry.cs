// OpenDLP Agent - GPL-3.0-only
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace OpenDLP.Agent;

public sealed class ServerClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly string _base;
    private readonly string _agentId;
    private readonly byte[] _verifyKey;
    private readonly ECDsa? _pubKey;

    public ServerClient(AgentConfig cfg)
    {
        _base = cfg.ServerUrl.TrimEnd('/');
        _agentId = cfg.AgentId;
        _verifyKey = cfg.PolicyVerifyKey();
        _pubKey = PolicySignature.LoadPublicKey(cfg.PolicySigningPublicKey);
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
        _http.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", $"Bearer {cfg.ApiToken}");
        _http.DefaultRequestHeaders.TryAddWithoutValidation("X-Agent-Id", cfg.AgentId);
        _http.DefaultRequestHeaders.TryAddWithoutValidation("X-Agent-Version", AgentVersion.Value);
    }

    /// <summary>Upload events from the durable on-disk outbox; the cursor only advances after the server accepted the batch.</summary>
    public async Task RunUploadLoopAsync(DiskOutbox outbox, IAlertLogger logger, CancellationToken ct)
    {
        const int baseDelayMs = 3000;
        var backoffMs = baseDelayMs;
        var wasFailing = false;

        while (!ct.IsCancellationRequested)
        {
            var failed = false;
            var more = false;
            try
            {
                var (batch, next) = outbox.ReadBatch(50);
                if (batch.Count == 0)
                {
                    outbox.Commit(next);
                }
                else
                {
                    var payload = new
                    {
                        agentId = _agentId,
                        sentAt = DateTime.UtcNow.ToString("o"),
                        events = batch.Select(x => JsonSerializer.Deserialize<JsonElement>(x)).ToList()
                    };

                    using var resp = await _http.PostAsJsonAsync($"{_base}/api/v1/telemetry", payload, ct);
                    if (resp.IsSuccessStatusCode)
                    {
                        outbox.Commit(next);
                        more = batch.Count >= 50;
                    }
                    else
                    {
                        failed = true;
                        if (!wasFailing) logger.Warn("TELEMETRY", $"Upload rejected: HTTP {(int)resp.StatusCode}");
                    }
                }
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                failed = true;
                if (!wasFailing) logger.Warn("TELEMETRY", $"Upload failed: {ex.Message}");
            }

            if (failed)
            {
                wasFailing = true;
                backoffMs = Math.Min(backoffMs * 2, 60_000);
            }
            else
            {
                if (wasFailing) logger.Info("TELEMETRY", "Upload recovered");
                wasFailing = false;
                backoffMs = baseDelayMs;
            }

            if (!failed && more) continue;
            try { await Task.Delay(backoffMs, ct); } catch (OperationCanceledException) { break; }
        }
    }

    /// <summary>Poll the server for policy. This doubles as the agent heartbeat the server uses to detect "offline" agents.</summary>
    public async Task RunPolicyLoopAsync(PolicyStore store, int pollSeconds, IAlertLogger logger, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                using var resp = await _http.GetAsync($"{_base}/api/v1/policy?version={store.Current.Version}", ct);
                if (resp.StatusCode == HttpStatusCode.NotModified)
                {
                    // Policy is unchanged; this is a normal polling result, not a warning.
                }
                else if (resp.IsSuccessStatusCode)
                {
                    var env = await resp.Content.ReadFromJsonAsync<PolicyEnvelope>(cancellationToken: ct);
                    if (env == null || string.IsNullOrEmpty(env.PolicyJson))
                    {
                        logger.Warn("POLICY", "Empty policy response");
                    }
                    else if (!VerifySig(env))
                    {
                        logger.Alert("POLICY_SIG_INVALID", "severity=high Policy signature mismatch; keeping current policy");
                    }
                    else if (store.Apply(env))
                    {
                        logger.Info("POLICY_UPDATED", $"Policy version {env.Version} applied");
                    }
                }
                else if (!resp.IsSuccessStatusCode)
                {
                    logger.Warn("POLICY", $"Policy fetch failed: HTTP {(int)resp.StatusCode}");
                }
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                logger.Warn("POLICY", $"Policy fetch error: {ex.Message}");
            }

            try { await Task.Delay(TimeSpan.FromSeconds(pollSeconds), ct); } catch (OperationCanceledException) { break; }
        }
    }

    private bool VerifySig(PolicyEnvelope env)
    {
        var data = Encoding.UTF8.GetBytes(env.PolicyJson);
        var mac = HMACSHA256.HashData(_verifyKey, data);
        var expected = Convert.ToHexString(mac).ToLowerInvariant();
        var hmacOk = CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(expected), Encoding.ASCII.GetBytes(env.Sig.ToLowerInvariant()));
        if (!hmacOk) return false;
        // If a public key is configured, the asymmetric signature is mandatory.
        return _pubKey == null || PolicySignature.Verify(_pubKey, data, env.PubSig);
    }

    public void Dispose()
    {
        _http.Dispose();
        _pubKey?.Dispose();
    }
}

/// <summary>ECDSA P-256 / SHA-256 policy signature helpers (DER signature, base64 in the envelope).</summary>
public static class PolicySignature
{
    public static ECDsa? LoadPublicKey(string pem)
    {
        if (string.IsNullOrWhiteSpace(pem)) return null;
        var key = ECDsa.Create();
        key.ImportFromPem(pem);
        return key;
    }

    public static bool Verify(ECDsa key, byte[] data, string? pubSigBase64)
    {
        if (string.IsNullOrWhiteSpace(pubSigBase64)) return false;
        try
        {
            var sig = Convert.FromBase64String(pubSigBase64);
            return key.VerifyData(data, sig, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3240DerSequence);
        }
        catch (FormatException) { return false; }
        catch (CryptographicException) { return false; }
    }
}
