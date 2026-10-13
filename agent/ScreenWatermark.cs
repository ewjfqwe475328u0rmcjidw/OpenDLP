// OpenDLP Agent - GPL-3.0-only
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Text;
using System.Windows.Forms;

namespace OpenDLP.Agent;

/// <summary>
/// Faint, click-through text tiled across every monitor ("user · host · date"). It shows up in photos of the screen,
/// screenshots and screen shares, so leaked images can be traced and people think twice. Runs in the user-session
/// helper; follows the policy (on/off, text, opacity) and monitor changes.
/// </summary>
public sealed class ScreenWatermark : IDisposable
{
    private readonly PolicyStore _policy;
    private readonly IAlertLogger _logger;
    private Thread? _thread;
    private volatile bool _stop;

    public ScreenWatermark(PolicyStore policy, IAlertLogger logger)
    {
        _policy = policy;
        _logger = logger;
    }

    public static string Render(string template, string user, string host, DateTime now)
    {
        var text = string.IsNullOrWhiteSpace(template) ? "{user} · {host} · {date}" : template;
        text = text.Replace("{user}", user).Replace("{host}", host)
            .Replace("{date}", now.ToString("yyyy-MM-dd")).Replace("{time}", now.ToString("HH:mm"));
        return text.Length > 120 ? text[..120] : text;
    }

    public static double ClampOpacity(double v) => double.IsNaN(v) ? 0.08 : Math.Clamp(v, 0.03, 0.35);

    public void Start()
    {
        _thread = new Thread(Run) { IsBackground = true, Name = "OpenDLP.Watermark" };
        _thread.SetApartmentState(ApartmentState.STA);
        _thread.Start();
    }

    public void Dispose()
    {
        _stop = true;
    }

    private void Run()
    {
        var forms = new List<WatermarkForm>();
        string? shownKey = null;
        var timer = new System.Windows.Forms.Timer { Interval = 5000 };

        void Refresh()
        {
            if (_stop) { Application.ExitThread(); return; }
            var p = _policy.Current.Watermark;
            var text = Render(p.Text, Environment.UserName, Environment.MachineName, DateTime.Now);
            var screens = string.Join(";", Screen.AllScreens.Select(s => s.Bounds.ToString()));
            var key = p.Enabled ? $"{text}|{ClampOpacity(p.Opacity)}|{p.FontSize}|{screens}" : null;
            if (key == shownKey) return;
            foreach (var f in forms) f.Close();
            forms.Clear();
            shownKey = key;
            if (key == null) return;
            foreach (var s in Screen.AllScreens)
            {
                var f = new WatermarkForm(s.Bounds, text, ClampOpacity(p.Opacity), Math.Clamp(p.FontSize, 8, 48));
                f.Show();
                forms.Add(f);
            }
            _logger.Info("WATERMARK", $"Screen watermark shown on {forms.Count} display(s)");
        }

        timer.Tick += (_, _) => Refresh();
        Microsoft.Win32.SystemEvents.DisplaySettingsChanged += (_, _) => shownKey = "";
        timer.Start();
        Refresh();
        Application.Run();
        timer.Dispose();
    }
}

public sealed class WatermarkForm : Form
{
    private const int WS_EX_LAYERED = 0x00080000;
    private const int WS_EX_TRANSPARENT = 0x00000020;
    private const int WS_EX_TOOLWINDOW = 0x00000080;
    private const int WS_EX_NOACTIVATE = 0x08000000;
    private const int WS_EX_TOPMOST = 0x00000008;
    public const int RequiredExStyle = WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE | WS_EX_TOPMOST;

    private static readonly Color Key = Color.FromArgb(255, 1, 2, 3);
    private readonly string _text;
    private readonly int _fontSize;

    public WatermarkForm(Rectangle bounds, string text, double opacity, int fontSize)
    {
        _text = text;
        _fontSize = fontSize;
        FormBorderStyle = FormBorderStyle.None;
        ShowInTaskbar = false;
        StartPosition = FormStartPosition.Manual;
        Bounds = bounds;
        TopMost = true;
        BackColor = Key;
        TransparencyKey = Key;
        Opacity = opacity;
        DoubleBuffered = true;
    }

    /// <summary>Click-through, never takes focus, not in Alt-Tab, always on top.</summary>
    protected override CreateParams CreateParams
    {
        get
        {
            var cp = base.CreateParams;
            cp.ExStyle |= RequiredExStyle;
            return cp;
        }
    }

    public int ExStyleForTest => CreateParams.ExStyle;

    protected override bool ShowWithoutActivation => true;

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.TextRenderingHint = TextRenderingHint.AntiAliasGridFit;
        using var font = new Font("Segoe UI", _fontSize, FontStyle.Bold, GraphicsUnit.Point);
        using var brush = new SolidBrush(Color.FromArgb(255, 128, 128, 128));
        var size = g.MeasureString(_text, font);
        var stepX = (int)size.Width + 120;
        var stepY = (int)size.Height + 110;
        g.TranslateTransform(Width / 2f, Height / 2f);
        g.RotateTransform(-25);
        var reach = (int)Math.Sqrt(Width * Width + Height * Height);
        for (var y = -reach; y < reach; y += stepY)
        {
            var offset = (y / stepY % 2 == 0) ? 0 : stepX / 2;
            for (var x = -reach; x < reach; x += stepX)
                g.DrawString(_text, font, brush, x + offset, y);
        }
    }
}
