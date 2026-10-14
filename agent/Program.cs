// Leakwarden Agent - GPL-3.0-only
// Copyright (C) Leakwarden Contributors
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License v3. It is distributed WITHOUT ANY WARRANTY.
//
// Usage:
//   Leakwarden.Agent.exe --mode service            (started by the Windows Service Control Manager)
//   Leakwarden.Agent.exe --mode helper             (per-user, hidden; clipboard monitor)
//   Leakwarden.Agent.exe --mode console            (all-in-one foreground, for development)
//   Leakwarden.Agent.exe --decrypt <logfile>       (print a local encrypted log)

using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.WindowsServices;

namespace Leakwarden.Agent;

internal static class Program
{
    private static int Main(string[] args)
    {
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        var baseDir = AppContext.BaseDirectory;
        Directory.SetCurrentDirectory(baseDir);

        var mode = ParseMode(args);
        var configPath = Path.Combine(baseDir, "agent.config.json");

        AgentConfig config;
        try
        {
            // The helper runs as an ordinary user and must never read the secret config file
            config = mode == RunMode.Helper ? AgentConfig.Defaults() : AgentConfig.Load(configPath);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Config error: {ex.Message}");
            return 2;
        }

        var di = Array.IndexOf(args, "--decrypt");
        if (di >= 0 && di + 1 < args.Length)
            return DecryptFile(args[di + 1], config);

        Console.WriteLine($"Leakwarden Endpoint Agent v{AgentVersion.Value} | GPLv3");
        Console.WriteLine("WARNING: Experimental MVP. Windows/.NET build and endpoint behavior have NOT yet been validated by the maintainers.");
        Console.WriteLine("Use only on an authorized test device. Do not rely on this agent as your only data-loss-prevention control.");
        Console.WriteLine($"Mode: {mode}\n");

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 17763))
            Ocr.PlatformEngine = WindowsOcr.RecognizeAsync;

        var builder = Host.CreateApplicationBuilder(args);
        builder.Services.AddSingleton(config);
        builder.Services.AddSingleton(new RunContext(mode));
        if (mode == RunMode.Service)
            builder.Services.AddWindowsService(o => o.ServiceName = "LeakwardenAgent");
        builder.Services.AddHostedService<AgentWorker>();

        builder.Build().Run();
        return 0;
    }

    private static RunMode ParseMode(string[] args)
    {
        var i = Array.IndexOf(args, "--mode");
        if (i >= 0 && i + 1 < args.Length)
        {
            switch (args[i + 1].ToLowerInvariant())
            {
                case "service": return RunMode.Service;
                case "helper": return RunMode.Helper;
                case "console": return RunMode.Console;
            }
        }
        return WindowsServiceHelpers.IsWindowsService() ? RunMode.Service : RunMode.Console;
    }

    private static int DecryptFile(string path, AgentConfig config)
    {
        var key = config.DeriveLogKey();
        foreach (var line in File.ReadLines(path))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            try { Console.WriteLine(SecureLog.Decrypt(line, key)); }
            catch { Console.WriteLine("[corrupted or tampered line]"); }
        }
        return 0;
    }
}
