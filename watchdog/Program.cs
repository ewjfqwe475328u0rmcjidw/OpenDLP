// Leakwarden Watchdog - GPL-3.0-only
using System.Diagnostics;
using System.ServiceProcess;

namespace Leakwarden.Watchdog;

internal static class Program
{
    // Usage:
    //   Service deployment (recommended, what install-service.ps1 registers):
    //     Leakwarden.Watchdog.exe --service LeakwardenAgent [--heartbeat "%ProgramData%\Leakwarden\logs\agent.heartbeat"]
    //   Stand-alone process (development):
    //     Leakwarden.Watchdog.exe --agent "C:\path\Leakwarden.Agent.exe" [--heartbeat ...]
    //   Optional: --stale-seconds 15 --interval-seconds 5 --once
    static async Task<int> Main(string[] args)
    {
        var serviceName = GetArg(args, "--service");
        var agentPath = GetArg(args, "--agent");
        if (serviceName == null && agentPath == null)
        {
            Console.Error.WriteLine("Specify --service <name> or --agent <path>");
            return 2;
        }

        var heartbeat = Environment.ExpandEnvironmentVariables(
            GetArg(args, "--heartbeat") ?? "%ProgramData%\\Leakwarden\\logs\\agent.heartbeat");
        var staleSeconds = int.TryParse(GetArg(args, "--stale-seconds"), out var s) ? s : 15;
        var intervalSeconds = int.TryParse(GetArg(args, "--interval-seconds"), out var iv) ? iv : 5;
        var once = args.Contains("--once", StringComparer.OrdinalIgnoreCase);
        const int graceSeconds = 15; // after a restart, give the agent time to write its first heartbeat

        Console.WriteLine($"Leakwarden Watchdog started ({(serviceName != null ? $"service {serviceName}" : agentPath)})");
        Console.WriteLine($"Heartbeat: {heartbeat} (stale after {staleSeconds}s)");

        while (true)
        {
            try
            {
                var fresh = File.Exists(heartbeat) &&
                            (DateTime.UtcNow - File.GetLastWriteTimeUtc(heartbeat)).TotalSeconds <= staleSeconds;

                var restarted = serviceName != null
                    ? CheckService(serviceName, fresh)
                    : CheckProcess(agentPath!, fresh);

                if (restarted)
                {
                    await Task.Delay(TimeSpan.FromSeconds(graceSeconds));
                    if (once) return 0;
                    continue;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Watchdog error: {ex.Message}");
            }

            if (once) return 0;
            await Task.Delay(TimeSpan.FromSeconds(intervalSeconds));
        }
    }

    /// <summary>Restart the Windows service if it is stopped or its heartbeat went stale (hung).</summary>
    private static bool CheckService(string name, bool heartbeatFresh)
    {
        using var sc = new ServiceController(name);
        sc.Refresh();
        var status = sc.Status;

        if (status is ServiceControllerStatus.StartPending or ServiceControllerStatus.StopPending
            or ServiceControllerStatus.ContinuePending or ServiceControllerStatus.PausePending)
            return false; // SCM is already acting

        if (status == ServiceControllerStatus.Running && heartbeatFresh) return false;

        Log($"Service {name} unhealthy (status={status}, heartbeatFresh={heartbeatFresh}). Restarting...");
        if (status == ServiceControllerStatus.Running)
        {
            // Hung: running but no heartbeat. Stop it (kill if it does not stop in time).
            try
            {
                sc.Stop();
                sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(20));
            }
            catch
            {
                foreach (var p in Process.GetProcessesByName("Leakwarden.Agent"))
                {
                    try { p.Kill(true); } catch { }
                }
                sc.Refresh();
                try { sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(10)); } catch { }
            }
        }

        sc.Refresh();
        if (sc.Status == ServiceControllerStatus.Stopped)
        {
            sc.Start();
            sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
            Log($"Service {name} is {sc.Status}");
        }
        return true;
    }

    /// <summary>Development mode: keep a stand-alone agent process alive.</summary>
    private static bool CheckProcess(string agentPath, bool heartbeatFresh)
    {
        var procName = Path.GetFileNameWithoutExtension(agentPath);
        var running = Process.GetProcessesByName(procName).Any();
        if (running && heartbeatFresh) return false;

        Log($"Agent unhealthy (heartbeatFresh={heartbeatFresh}, running={running}). Restarting...");
        foreach (var p in Process.GetProcessesByName(procName))
        {
            try { p.Kill(true); } catch { }
        }
        Process.Start(new ProcessStartInfo
        {
            FileName = agentPath,
            Arguments = "--mode console",
            UseShellExecute = true,
            WorkingDirectory = Path.GetDirectoryName(agentPath)
        });
        return true;
    }

    private static void Log(string msg) => Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] {msg}");

    static string? GetArg(string[] args, string name)
    {
        for (int i = 0; i < args.Length - 1; i++)
            if (args[i].Equals(name, StringComparison.OrdinalIgnoreCase))
                return args[i + 1];
        return null;
    }
}
