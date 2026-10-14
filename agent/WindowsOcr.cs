// Leakwarden Agent - GPL-3.0-only
using System.Runtime.Versioning;
using Windows.Graphics.Imaging;
using Windows.Media.Ocr;
using Windows.Storage.Streams;

namespace Leakwarden.Agent;

/// <summary>Built-in Windows 10/11 OCR (Windows.Media.Ocr): no download, runs on the device, uses the installed languages.</summary>
[SupportedOSPlatform("windows10.0.17763.0")]
public static class WindowsOcr
{
    private static OcrEngine? _engine;
    private static bool _tried;

    public static bool Available => Engine() != null;

    private static OcrEngine? Engine()
    {
        if (_tried) return _engine;
        _tried = true;
        try
        {
            _engine = OcrEngine.TryCreateFromUserProfileLanguages();
            if (_engine == null)
                foreach (var lang in OcrEngine.AvailableRecognizerLanguages)
                    if ((_engine = OcrEngine.TryCreateFromLanguage(lang)) != null) break;
        }
        catch (Exception) { _engine = null; }
        return _engine;
    }

    public static async Task<string?> RecognizeAsync(string path, CancellationToken ct)
    {
        var engine = Engine();
        if (engine == null) return null;
        var bytes = await File.ReadAllBytesAsync(path, ct);
        using var stream = new InMemoryRandomAccessStream();
        using (var writer = new DataWriter(stream.GetOutputStreamAt(0)))
        {
            writer.WriteBytes(bytes);
            await writer.StoreAsync();
            await writer.FlushAsync();
            writer.DetachStream();
        }
        stream.Seek(0);
        var decoder = await BitmapDecoder.CreateAsync(stream);
        var max = OcrEngine.MaxImageDimension;
        var transform = new BitmapTransform();
        var scale = Math.Min(1.0, Math.Min((double)max / decoder.PixelWidth, (double)max / decoder.PixelHeight));
        if (scale < 1.0)
        {
            transform.ScaledWidth = (uint)(decoder.PixelWidth * scale);
            transform.ScaledHeight = (uint)(decoder.PixelHeight * scale);
        }
        using var bitmap = await decoder.GetSoftwareBitmapAsync(BitmapPixelFormat.Bgra8, BitmapAlphaMode.Premultiplied,
            transform, ExifOrientationMode.RespectExifOrientation, ColorManagementMode.DoNotColorManage);
        var result = await engine.RecognizeAsync(bitmap);
        return string.Join("\n", result.Lines.Select(l => l.Text));
    }
}
