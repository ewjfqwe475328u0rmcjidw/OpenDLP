// OpenDLP Agent - GPL-3.0-only
using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace OpenDLP.Agent;

/// <summary>
/// The user-session helper has no secrets: it forwards events to the SYSTEM service over a named pipe,
/// and the service logs/uploads them. (Local users can still inject events; they cannot read the token or logs.)
/// </summary>
public sealed class PipeAlertLogger : IAlertLogger, IDisposable
{
    public const string PipeName = "OpenDLP.Helper";

    private readonly BlockingCollection<string> _queue = new(1000);
    private readonly Thread _thread;
    private volatile bool _stop;

    public PipeAlertLogger()
    {
        _thread = new Thread(Pump) { IsBackground = true, Name = "OpenDLP.HelperPipe" };
        _thread.Start();
    }

    public void Info(string t, string m) => Send("INFO", t, m);
    public void Warn(string t, string m) => Send("WARN", t, m);
    public void Alert(string t, string m) => Send("ALERT", t, m);

    private void Send(string level, string type, string message)
    {
        var json = JsonSerializer.Serialize(new { level, eventType = type, message, user = Environment.UserName });
        _queue.TryAdd(json); // drop when full (service down for a long time)
    }

    private void Pump()
    {
        while (!_stop)
        {
            try
            {
                using var client = new NamedPipeClientStream(".", PipeName, PipeDirection.Out);
                client.Connect(3000);
                using var writer = new StreamWriter(client, new UTF8Encoding(false)) { AutoFlush = true };
                while (!_stop)
                {
                    if (_queue.TryTake(out var item, 1000)) writer.WriteLine(item);
                }
            }
            catch
            {
                Thread.Sleep(2000); // service not up yet / pipe broken: retry
            }
        }
    }

    public void Dispose() => _stop = true;
}

public sealed class HelperPipeServer
{
    private static readonly Regex TypeRx = new("^[A-Z0-9_]{1,48}$", RegexOptions.Compiled);
    private readonly IAlertLogger _logger;

    public HelperPipeServer(IAlertLogger logger) => _logger = logger;

    private static NamedPipeServerStream CreateServer()
    {
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
            PipeAccessRights.ReadWrite, AccessControlType.Allow));
        var self = WindowsIdentity.GetCurrent().User;
        if (self != null)
            security.AddAccessRule(new PipeAccessRule(self, PipeAccessRights.FullControl, AccessControlType.Allow));

        return NamedPipeServerStreamAcl.Create(
            PipeAlertLogger.PipeName, PipeDirection.In, NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 0, 0, security);
    }

    public async Task RunAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream? server = null;
            try
            {
                server = CreateServer();
                await server.WaitForConnectionAsync(ct);
                var client = server;
                server = null; // ownership moves to the handler
                _ = Task.Run(() => HandleClientAsync(client, ct), ct);
            }
            catch (OperationCanceledException)
            {
                server?.Dispose();
                break;
            }
            catch
            {
                server?.Dispose();
                try { await Task.Delay(1000, ct); } catch (OperationCanceledException) { break; }
            }
        }
    }

    private async Task HandleClientAsync(NamedPipeServerStream stream, CancellationToken ct)
    {
        try
        {
            using (stream)
            using (var reader = new StreamReader(stream, Encoding.UTF8))
            {
                var count = 0;
                string? line;
                while ((line = await reader.ReadLineAsync(ct)) != null)
                {
                    if (++count > 100_000) break; // per-connection cap
                    if (line.Length > 16_000) continue;
                    Process(line);
                }
            }
        }
        catch { /* client went away */ }
    }

    private void Process(string line)
    {
        try
        {
            using var doc = JsonDocument.Parse(line);
            var root = doc.RootElement;
            var level = root.GetProperty("level").GetString() ?? "INFO";
            var type = root.GetProperty("eventType").GetString() ?? "";
            var message = root.GetProperty("message").GetString() ?? "";
            var user = root.TryGetProperty("user", out var u) ? (u.GetString() ?? "?") : "?";

            if (!TypeRx.IsMatch(type)) type = "HELPER_EVENT";
            if (message.Length > 4000) message = message[..4000];
            var text = $"user={user} {message}";

            switch (level)
            {
                case "ALERT": _logger.Alert(type, text); break;
                case "WARN": _logger.Warn(type, text); break;
                default: _logger.Info(type, text); break;
            }
        }
        catch { /* malformed */ }
    }
}
