// OpenDLP Agent - GPL-3.0-only (shared by the Windows and macOS agents)
namespace OpenDLP.Agent;

public static class AgentVersion
{
    public static string Value =>
        typeof(AgentVersion).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
}
