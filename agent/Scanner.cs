// Leakwarden Agent - GPL-3.0-only
using System.Collections.Concurrent;
using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;

namespace Leakwarden.Agent;

public sealed record ScanHit(string RuleId, string RuleName, string Severity, string Action, int Count, string Sample);

/// <summary>Content inspection driven by the current policy. Never returns raw matched data (samples are masked).</summary>
public sealed class ContentScanner
{
    private static readonly TimeSpan RxTimeout = TimeSpan.FromSeconds(1);
    private const RegexOptions Opts = RegexOptions.Compiled | RegexOptions.CultureInvariant;

    private static readonly Regex NidRx = new(@"(?<![A-Za-z0-9])[A-Z][12]\d{8}(?!\d)", Opts, RxTimeout);
    private static readonly Regex CardRx = new(@"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)", Opts, RxTimeout);
    private static readonly Regex MobileRx = new(@"(?<!\d)09\d{2}[- ]?\d{3}[- ]?\d{3}(?!\d)", Opts, RxTimeout);
    private static readonly Regex EmailRx = new(@"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", Opts, RxTimeout);
    // Taiwan passport: 9 digits, first digit 1-3 (current series). Requires the word "passport"/"護照" nearby to limit false positives.
    private static readonly Regex PassportRx = new(@"(?i)(?:passport|護照)[^\d]{0,20}(?<![\d])([1-3]\d{8})(?!\d)", Opts, RxTimeout);
    // Common secret formats: AWS access key, GitHub/Slack/Google/Stripe/OpenAI-style tokens, generic "api_key=..." assignments.
    private static readonly Regex ApiKeyRx = new(
        @"(?:AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_\-]{35}|sk_(?:live|test)_[0-9A-Za-z]{16,}|sk-[A-Za-z0-9]{20,}|(?i:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*[""']?[A-Za-z0-9_\-]{16,})",
        Opts, RxTimeout);
    // US Social Security number: strict format, excludes impossible areas/groups (000, 666, 9xx) and well-known advertising numbers.
    private static readonly Regex SsnRx = new(@"(?<![\d-])(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\d-])", Opts, RxTimeout);
    // Generic passport: "passport" (several languages) followed by a 6-9 character alphanumeric number.
    private static readonly Regex PassportAnyRx = new(@"(?i)(?:passport|passeport|reisepass|pasaporte|passaporto|паспорт|护照|護照|パスポート|여권)[\s\S]{0,20}?(?<![A-Za-z0-9])(?=[A-Z]*\d)([A-Z0-9]{6,9})(?![A-Za-z0-9])", Opts, RxTimeout);
    private static readonly Regex PrivateKeyRx = new(@"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----", Opts, RxTimeout);
    private static readonly Regex IbanRx = new(@"(?<![A-Z0-9])[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}[ ]?[A-Z0-9]{1,4}(?![A-Z0-9])", Opts, RxTimeout);

    private readonly PolicyStore _policy;
    private readonly ConcurrentDictionary<string, Regex?> _custom = new();

    public ContentScanner(PolicyStore policy) => _policy = policy;

    public PolicyStore Policy => _policy;

    public List<ScanHit> Scan(string text)
    {
        var hits = new List<ScanHit>();
        if (string.IsNullOrEmpty(text)) return hits;

        foreach (var rule in _policy.Current.Rules)
        {
            try
            {
                var (count, sample) = Run(rule, text);
                if (count >= Math.Max(1, rule.MinMatches))
                    hits.Add(new ScanHit(rule.Id, rule.Name, rule.Severity, rule.Action.ToLowerInvariant(), count, sample));
            }
            catch (RegexMatchTimeoutException) { /* pathological input/pattern: skip rule */ }
            catch { /* bad rule: skip */ }
        }
        return hits;
    }

    public static string WorstSeverity(IEnumerable<ScanHit> hits)
    {
        static int Rank(string s) => s.ToLowerInvariant() switch { "critical" => 4, "high" => 3, "medium" => 2, _ => 1 };
        return hits.Select(h => h.Severity).OrderByDescending(Rank).FirstOrDefault() ?? "low";
    }

    public static string Summarize(IEnumerable<ScanHit> hits)
    {
        var list = hits.ToList();
        var rules = string.Join(",", list.Select(h => $"{h.RuleId}x{h.Count}"));
        var samples = string.Join(",", list.Select(h => $"{h.RuleId}:{h.Sample}"));
        return $"severity={WorstSeverity(list)} rules={rules} samples={samples}";
    }

    private (int, string) Run(ContentRule rule, string text)
    {
        switch (rule.Type.ToLowerInvariant())
        {
            case "builtin": return RunBuiltin(rule, text);
            case "keywords": return RunKeywords(rule.Keywords, text);
            case "regex": return RunRegex(rule.Pattern, text);
            default: return (0, "");
        }
    }

    /// <summary>Default words that make a builtin match credible when a rule sets requireContext.</summary>
    public static readonly IReadOnlyDictionary<string, string[]> DefaultContext = new Dictionary<string, string[]>
    {
        ["credit_card"] = new[] { "card", "credit", "visa", "mastercard", "amex", "payment", "cvv", "expiry", "信用卡", "卡號" },
        ["us_ssn"] = new[] { "ssn", "social security", "taxpayer" },
        ["iban"] = new[] { "iban", "bank", "account", "swift", "bic" },
        ["tw_national_id"] = new[] { "身分證", "身份證", "national id", "id no", "統一編號" },
        ["tw_mobile"] = new[] { "手機", "電話", "mobile", "phone", "tel" },
        ["email"] = new[] { "email", "e-mail", "mail", "信箱" },
    };

    private static (Regex Rx, Func<string, bool> Valid) B(Regex rx, Func<string, bool> valid) => (rx, valid);
    private static bool Any(string _) => true;

    private static (Regex Rx, Func<string, bool> Valid)? Builtin(string detector) => detector switch
    {
        "tw_national_id" => B(NidRx, IsValidTwNationalId),
        "credit_card" => B(CardRx, IsValidCard),
        "tw_mobile" => B(MobileRx, Any),
        "email" => B(EmailRx, Any),
        "tw_passport" => B(PassportRx, Any),
        "api_key" => B(ApiKeyRx, Any),
        "private_key" => B(PrivateKeyRx, Any),
        "iban" => B(IbanRx, IsValidIban),
        "us_ssn" => B(SsnRx, Any),
        "passport" => B(PassportAnyRx, Any),
        _ => null
    };

    private (int, string) RunBuiltin(ContentRule rule, string text)
    {
        var detector = rule.Detector.ToLowerInvariant();
        var b = Builtin(detector);
        if (b == null) return (0, "");

        var excludes = rule.Exclude.Select(GetRegex).Where(r => r != null).Cast<Regex>().ToList();
        string[] context = rule.ContextWords.Count > 0
            ? rule.ContextWords.ToArray()
            : DefaultContext.TryGetValue(detector, out var d) ? d : Array.Empty<string>();

        var n = 0;
        var sample = "";
        foreach (Match m in b.Value.Rx.Matches(text))
        {
            if (!b.Value.Valid(m.Value)) continue;
            if (excludes.Any(x => x.IsMatch(m.Value))) continue;
            if (rule.RequireContext && context.Length > 0 && !HasContext(text, m.Index, m.Length, context)) continue;
            n++;
            if (sample.Length == 0) sample = Mask(m.Value);
        }
        return (n, sample);
    }

    /// <summary>True when one of the words appears within 60 characters before or after the match.</summary>
    public static bool HasContext(string text, int index, int length, IEnumerable<string> words)
    {
        const int window = 60;
        var start = Math.Max(0, index - window);
        var end = Math.Min(text.Length, index + length + window);
        var around = text.Substring(start, end - start);
        return words.Any(w => !string.IsNullOrWhiteSpace(w) && around.Contains(w, StringComparison.OrdinalIgnoreCase));
    }

    private Regex? GetRegex(string pattern) => string.IsNullOrWhiteSpace(pattern) ? null : _custom.GetOrAdd(pattern, p =>
    {
        try { return new Regex(p, RegexOptions.CultureInvariant, RxTimeout); }
        catch { return null; }
    });

    private static (int, string) RunKeywords(List<string> keywords, string text)
    {
        var total = 0;
        var sample = "";
        foreach (var kw in keywords)
        {
            if (string.IsNullOrWhiteSpace(kw)) continue;
            var n = 0;
            var pos = 0;
            while ((pos = text.IndexOf(kw, pos, StringComparison.OrdinalIgnoreCase)) >= 0) { n++; pos += kw.Length; }
            if (n > 0 && sample.Length == 0) sample = kw;
            total += n;
        }
        return (total, sample);
    }

    private (int, string) RunRegex(string pattern, string text)
    {
        var rx = GetRegex(pattern);
        if (rx == null) return (0, "");

        var n = 0;
        var sample = "";
        foreach (Match m in rx.Matches(text))
        {
            n++;
            if (sample.Length == 0) sample = Mask(m.Value);
        }
        return (n, sample);
    }

    private static (int, string) CountValid(Regex rx, string text, Func<string, bool> valid)
    {
        var n = 0;
        var sample = "";
        foreach (Match m in rx.Matches(text))
        {
            if (!valid(m.Value)) continue;
            n++;
            if (sample.Length == 0) sample = Mask(m.Value);
        }
        return (n, sample);
    }

    public static string Mask(string s)
    {
        if (s.Length <= 4) return new string('*', s.Length);
        return s[..2] + new string('*', s.Length - 4) + s[^2..];
    }

    // Taiwan national ID checksum (weights 1,9,8,7,6,5,4,3,2,1,1 over letter-code + 9 digits)
    public static bool IsValidTwNationalId(string id)
    {
        const string letters = "ABCDEFGHJKLMNPQRSTUVXYWZIO";
        if (id.Length != 10) return false;
        var idx = letters.IndexOf(id[0]);
        if (idx < 0) return false;

        var code = idx + 10;
        int[] w = { 1, 9, 8, 7, 6, 5, 4, 3, 2, 1, 1 };
        var sum = (code / 10) * w[0] + (code % 10) * w[1];
        for (var i = 1; i <= 9; i++)
        {
            if (!char.IsDigit(id[i])) return false;
            sum += (id[i] - '0') * w[i + 1];
        }
        return sum % 10 == 0;
    }

    /// <summary>ISO 13616 mod-97 check.</summary>
    public static bool IsValidIban(string raw)
    {
        var iban = raw.Replace(" ", "").ToUpperInvariant();
        if (iban.Length < 15 || iban.Length > 34) return false;
        var rearranged = iban[4..] + iban[..4];
        var remainder = 0;
        foreach (var c in rearranged)
        {
            int v;
            if (char.IsDigit(c)) v = c - '0';
            else if (c >= 'A' && c <= 'Z') v = c - 'A' + 10;
            else return false;
            remainder = v < 10 ? (remainder * 10 + v) % 97 : (remainder * 100 + v) % 97;
        }
        return remainder == 1;
    }

    public static bool IsValidCard(string raw)
    {
        var digits = new List<int>();
        foreach (var c in raw) if (char.IsDigit(c)) digits.Add(c - '0');
        if (digits.Count < 13 || digits.Count > 19) return false;
        if (digits[0] < 3 || digits[0] > 6) return false; // Amex/JCB/Visa/MC/UnionPay/Discover leading digits

        var sum = 0;
        var dbl = false;
        for (var i = digits.Count - 1; i >= 0; i--)
        {
            var d = digits[i];
            if (dbl) { d *= 2; if (d > 9) d -= 9; }
            sum += d;
            dbl = !dbl;
        }
        return sum % 10 == 0;
    }
}

/// <summary>Best-effort text extraction (plain text and OOXML). PDFs and legacy .doc/.xls are not supported.</summary>
public static class TextExtractor
{
    private static readonly HashSet<string> TextExts = new(StringComparer.OrdinalIgnoreCase)
    {
        ".txt", ".csv", ".tsv", ".log", ".json", ".xml", ".md", ".html", ".htm", ".ini", ".yml", ".yaml", ".sql", ".eml"
    };

    static TextExtractor()
    {
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
    }

    private static readonly HashSet<string> OoxmlExts = new(StringComparer.OrdinalIgnoreCase) { ".docx", ".xlsx", ".pptx" };

    public static bool IsSupported(string path)
    {
        var ext = Path.GetExtension(path);
        return TextExts.Contains(ext) || OoxmlExts.Contains(ext) || ext.Equals(".zip", StringComparison.OrdinalIgnoreCase);
    }

    public static string? Extract(string path, int maxBytes)
    {
        try
        {
            var ext = Path.GetExtension(path).ToLowerInvariant();
            if (TextExts.Contains(ext)) return ReadText(path, maxBytes);

            if (ext == ".zip") return ReadZipArchive(path, maxBytes);
            if (!OoxmlExts.Contains(ext)) return null;
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return ReadOoxml(fs, ext, maxBytes);
        }
        catch
        {
            return null;
        }
    }

    private static string ReadText(string path, int maxBytes)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        var len = (int)Math.Min(fs.Length, maxBytes);
        var buf = new byte[len];
        var total = 0;
        while (total < len)
        {
            var r = fs.Read(buf, total, len - total);
            if (r <= 0) break;
            total += r;
        }

        if (total >= 2 && buf[0] == 0xFF && buf[1] == 0xFE) return Encoding.Unicode.GetString(buf, 2, total - 2);
        if (total >= 2 && buf[0] == 0xFE && buf[1] == 0xFF) return Encoding.BigEndianUnicode.GetString(buf, 2, total - 2);

        var utf8 = Encoding.UTF8.GetString(buf, 0, total);
        // Many Taiwanese CSV/TXT exports are Big5: if UTF-8 decoding produced replacement chars, scan the Big5 decoding too.
        if (utf8.Contains('\uFFFD'))
        {
            try { return utf8 + "\n" + Encoding.GetEncoding(950).GetString(buf, 0, total); }
            catch { /* codepage unavailable */ }
        }
        return utf8;
    }

    private static Func<string, bool>? OoxmlParts(string ext) => ext switch
    {
        ".docx" => n => n == "word/document.xml",
        ".xlsx" => n => n == "xl/sharedStrings.xml" ||
                        (n.StartsWith("xl/worksheets/", StringComparison.Ordinal) && n.EndsWith(".xml", StringComparison.Ordinal)),
        ".pptx" => n => n.StartsWith("ppt/slides/slide", StringComparison.Ordinal) && n.EndsWith(".xml", StringComparison.Ordinal),
        _ => null
    };

    private static string ReadOoxml(Stream stream, string ext, int maxBytes)
    {
        var pick = OoxmlParts(ext.ToLowerInvariant());
        if (pick == null) return "";
        using var zip = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);

        var sb = new StringBuilder();
        long budget = maxBytes;

        foreach (var entry in zip.Entries)
        {
            if (!pick(entry.FullName)) continue;
            var xml = Encoding.UTF8.GetString(ReadCapped(entry, (int)Math.Min(budget, 8 * 1024 * 1024)));   // zip-bomb guard
            sb.Append(Regex.Replace(xml, "<[^>]+>", " ")).Append(' ');
            budget -= xml.Length;
            if (budget <= 0) break;
        }
        return sb.ToString();
    }

    private static byte[] ReadCapped(ZipArchiveEntry entry, int cap)
    {
        using var s = entry.Open();
        var buf = new byte[Math.Max(0, cap)];
        var total = 0;
        while (total < buf.Length)
        {
            var r = s.Read(buf, total, buf.Length - total);
            if (r <= 0) break;
            total += r;
        }
        return buf.AsSpan(0, total).ToArray();
    }

    /// <summary>
    /// Text of supported files inside a .zip (one level; Office files inside are opened too).
    /// Bounded: at most 200 entries and maxBytes of decompressed data. Encrypted entries are skipped.
    /// </summary>
    private static string ReadZipArchive(string path, int maxBytes)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var zip = new ZipArchive(fs, ZipArchiveMode.Read);
        var sb = new StringBuilder();
        long budget = maxBytes;
        var seen = 0;
        foreach (var entry in zip.Entries)
        {
            if (++seen > 200 || budget <= 0) break;
            if (entry.Length == 0 || entry.FullName.EndsWith('/')) continue;
            var ext = Path.GetExtension(entry.Name);
            try
            {
                if (TextExts.Contains(ext))
                {
                    var bytes = ReadCapped(entry, (int)Math.Min(budget, 8 * 1024 * 1024));
                    budget -= bytes.Length;
                    sb.Append(Encoding.UTF8.GetString(bytes)).Append('\n');
                }
                else if (OoxmlExts.Contains(ext) && entry.Length <= 16 * 1024 * 1024)
                {
                    using var ms = new MemoryStream(ReadCapped(entry, 16 * 1024 * 1024));
                    var text = ReadOoxml(ms, ext, (int)Math.Max(0, budget));
                    budget -= text.Length;
                    sb.Append(text).Append('\n');
                }
            }
            catch (InvalidDataException) { /* encrypted / corrupt entry */ }
        }
        return sb.ToString();
    }

    /// <summary>SHA-256 (lower-case hex) of a file and of each file inside it when it is a .zip; bounded.</summary>
    public static IEnumerable<(string Name, string Sha256)> Hashes(string path, long maxFileBytes = 100L * 1024 * 1024)
    {
        var info = new FileInfo(path);
        if (!info.Exists || info.Length > maxFileBytes) yield break;
        string own;
        using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            own = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(fs)).ToLowerInvariant();
        yield return (Path.GetFileName(path), own);

        if (!path.EndsWith(".zip", StringComparison.OrdinalIgnoreCase)) yield break;
        var list = new List<(string, string)>();
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var zip = new ZipArchive(fs, ZipArchiveMode.Read);
            foreach (var e in zip.Entries.Take(500))
            {
                if (e.Length == 0 || e.Length > maxFileBytes || e.FullName.EndsWith('/')) continue;
                try
                {
                    using var es = e.Open();
                    list.Add((e.FullName, Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(es)).ToLowerInvariant()));
                }
                catch (InvalidDataException) { }
            }
        }
        catch (InvalidDataException) { }
        foreach (var x in list) yield return x;
    }
}
