// OpenDLP Watchdog - GPL-3.0-only
using System.Diagnostics;

namespace OpenDLP.Watchdog;

internal static class Program
{
    // 用法:
    // OpenDLP.Watchdog.exe --agent "C:\path\OpenDLP.Agent.exe" --heartbeat "%ProgramData%\OpenDLP\logs\agent.heartbeat"
    static async Task Main(string[] args)
    {
        var agentPath = GetArg(args, "--agent") ?? throw new ArgumentException("--agent required");
        var heartbeat = Environment.ExpandEnvironmentVariables(
            GetArg(args, "--heartbeat") ?? "%ProgramData%\\OpenDLP\\logs\\agent.heartbeat");
        var staleSeconds = 15;
        var graceSeconds = 10; // 重啟後給 agent 時間寫第一個 heartbeat
        var procName = Path.GetFileNameWithoutExtension(agentPath);

        Console.WriteLine("OpenDLP Watchdog started");
        Console.WriteLine($"Agent: {agentPath}");
        Console.WriteLine($"Heartbeat: {heartbeat}");

        while (true)
        {
            try
            {
                var alive = File.Exists(heartbeat) &&
                            (DateTime.UtcNow - File.GetLastWriteTimeUtc(heartbeat)).TotalSeconds <= staleSeconds;

                var running = Process.GetProcessesByName(procName).Any();

                if (!alive || !running)
                {
                    Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Agent unhealthy (alive={alive}, running={running}). Restarting...");
                    foreach (var p in Process.GetProcessesByName(procName))
                    {
                        try { p.Kill(true); } catch { }
                    }

                    var psi = new ProcessStartInfo
                    {
                        FileName = agentPath,
                        UseShellExecute = true,
                        WorkingDirectory = Path.GetDirectoryName(agentPath)
                    };
                    Process.Start(psi);

                    await Task.Delay(TimeSpan.FromSeconds(graceSeconds));
                    continue;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Watchdog error: {ex.Message}");
            }

            await Task.Delay(5000);
        }
    }

    static string? GetArg(string[] args, string name)
    {
        for (int i = 0; i < args.Length - 1; i++)
            if (args[i].Equals(name, StringComparison.OrdinalIgnoreCase))
                return args[i + 1];
        return null;
    }
}
