using System.Drawing;
using System.Drawing.Imaging;
using OpenDLP.Agent;
using Xunit;
using Xunit.Abstractions;

namespace OpenDLP.Agent.Tests;

public class OcrTests
{
    private readonly ITestOutputHelper _out;
    public OcrTests(ITestOutputHelper output) => _out = output;

    [Fact]
    public void RecognisesImageExtensions()
    {
        Assert.True(Ocr.IsImage(@"C:\x\Screenshot 2026.PNG"));
        Assert.True(Ocr.IsImage("scan.jpeg"));
        Assert.False(Ocr.IsImage("report.pdf"));
        Assert.False(Ocr.IsImage("notes.txt"));
    }

    [Fact]
    public void RateLimitCapsRecognitionsPerMinute()
    {
        Ocr.ResetRateLimit();
        var t0 = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        Assert.True(Ocr.TryAcquire(2, t0));
        Assert.True(Ocr.TryAcquire(2, t0.AddSeconds(1)));
        Assert.False(Ocr.TryAcquire(2, t0.AddSeconds(2)));
        Assert.True(Ocr.TryAcquire(2, t0.AddSeconds(61)));
        Ocr.ResetRateLimit();
    }

    [Fact]
    public async Task DisabledPolicyOrOversizedImageIsSkipped()
    {
        var path = Path.Combine(Path.GetTempPath(), $"ocr-{Guid.NewGuid():N}.png");
        await File.WriteAllBytesAsync(path, new byte[2048]);
        try
        {
            Assert.Null(await Ocr.RecognizeAsync(path, new OcrPolicy { Enabled = false }, CancellationToken.None));
            Assert.Null(await Ocr.RecognizeAsync(path, new OcrPolicy { Enabled = true, MaxImageBytes = 100 }, CancellationToken.None));
        }
        finally { File.Delete(path); }
    }

    /// <summary>Real recognition with the built-in Windows engine when the OS has an OCR language installed.</summary>
    [Fact]
    public async Task WindowsOcrReadsACardNumberFromAScreenshot()
    {
        if (!WindowsOcr.Available)
        {
            _out.WriteLine("Windows OCR engine not available on this machine (no OCR language installed); skipped.");
            return;
        }
        var path = Path.Combine(Path.GetTempPath(), $"ocr-{Guid.NewGuid():N}.png");
        using (var bmp = new Bitmap(1000, 260))
        using (var g = Graphics.FromImage(bmp))
        using (var font = new Font("Arial", 40, FontStyle.Regular, GraphicsUnit.Pixel))
        {
            g.Clear(Color.White);
            g.DrawString("Customer payment details", font, Brushes.Black, 30, 40);
            g.DrawString("Card: 4111 1111 1111 1111", font, Brushes.Black, 30, 150);
            bmp.Save(path, ImageFormat.Png);
        }
        try
        {
            string? text;
            try { text = await WindowsOcr.RecognizeAsync(path, CancellationToken.None); }
            catch (Exception ex) { throw new Xunit.Sdk.XunitException($"OCR text: <exception> {ex.GetType().Name}: {ex.Message}"); }
            _out.WriteLine($"OCR text: {text}");
            Assert.True(text != null, "OCR text: <null>");
            var policy = new PolicyStore(Path.Combine(Path.GetTempPath(), "none.json"), Path.Combine(AppContext.BaseDirectory, "policy.default.json"));
            policy.LoadFromDisk();
            var hits = new ContentScanner(policy).Scan(text!);
            Assert.True(hits.Any(h => h.RuleId == "CREDIT-CARD"),
                $"OCR text: [{text!.Replace("\r", " ").Replace("\n", " | ")}] rules: [{string.Join(",", hits.Select(h => h.RuleId))}]");
        }
        finally { File.Delete(path); }
    }
}

public class WatermarkTests
{
    [Fact]
    public void RendersPlaceholders()
    {
        var now = new DateTime(2026, 10, 13, 9, 5, 0);
        Assert.Equal("alice · PC-7 · 2026-10-13 09:05", ScreenWatermark.Render("{user} · {host} · {date} {time}", "alice", "PC-7", now));
        Assert.Equal("bob · H · 2026-10-13", ScreenWatermark.Render("", "bob", "H", now));
        Assert.Equal(120, ScreenWatermark.Render(new string('x', 500), "u", "h", now).Length);
    }

    [Fact]
    public void OpacityIsClampedSoTheWatermarkStaysSubtleButVisible()
    {
        Assert.Equal(0.03, ScreenWatermark.ClampOpacity(0));
        Assert.Equal(0.35, ScreenWatermark.ClampOpacity(1));
        Assert.Equal(0.1, ScreenWatermark.ClampOpacity(0.1));
    }

    [Fact]
    public void OverlayIsClickThroughTopmostAndHiddenFromAltTab()
    {
        using var f = new WatermarkForm(new Rectangle(0, 0, 200, 100), "x", 0.08, 16);
        Assert.Equal(WatermarkForm.RequiredExStyle, f.ExStyleForTest & WatermarkForm.RequiredExStyle);
        Assert.False(f.ShowInTaskbar);
    }

    [Fact]
    public void DefaultPolicyHasOcrOnAndWatermarkOff()
    {
        var policy = new PolicyStore(Path.Combine(Path.GetTempPath(), "none.json"), Path.Combine(AppContext.BaseDirectory, "policy.default.json"));
        policy.LoadFromDisk();
        Assert.True(policy.Current.Ocr.Enabled);
        Assert.False(policy.Current.Watermark.Enabled);
        Assert.Equal(0.08, policy.Current.Watermark.Opacity);
    }
}
