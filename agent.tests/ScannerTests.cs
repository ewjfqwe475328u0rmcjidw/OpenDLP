// OpenDLP Agent tests - GPL-3.0-only
using System.Text.Json;
using OpenDLP.Agent;
using Xunit;

public class ValidatorTests
{
    [Theory]
    [InlineData("A123456789", true)]   // classic valid sample
    [InlineData("A123456788", false)]  // bad checksum
    [InlineData("Z999999999", false)]
    [InlineData("A12345678", false)]   // too short
    public void TaiwanNationalIdChecksum(string id, bool expected) =>
        Assert.Equal(expected, ContentScanner.IsValidTwNationalId(id));

    [Theory]
    [InlineData("4111 1111 1111 1111", true)]
    [InlineData("5500-0000-0000-0004", true)]
    [InlineData("4111 1111 1111 1112", false)]
    [InlineData("1234 5678 9012 3456", false)] // leading digit outside card ranges
    public void CardLuhn(string card, bool expected) =>
        Assert.Equal(expected, ContentScanner.IsValidCard(card));

    [Theory]
    [InlineData("GB82 WEST 1234 5698 7654 32", true)]
    [InlineData("DE89 3704 0044 0532 0130 00", true)]
    [InlineData("GB82 WEST 1234 5698 7654 33", false)]
    public void IbanMod97(string iban, bool expected) =>
        Assert.Equal(expected, ContentScanner.IsValidIban(iban));

    [Fact]
    public void MaskHidesMiddle()
    {
        Assert.Equal("A1******89", ContentScanner.Mask("A123456789"));
        Assert.Equal("****", ContentScanner.Mask("abcd"));
    }
}

public class ScannerTests
{
    private static ContentScanner Build(params object[] rules)
    {
        var dir = Path.Combine(Path.GetTempPath(), "opendlp-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var store = new PolicyStore(Path.Combine(dir, "cache.json"), Path.Combine(dir, "missing.json"));
        var env = new PolicyEnvelope
        {
            Version = 1,
            PolicyJson = JsonSerializer.Serialize(new { rules }),
            Sig = "unverified-in-unit-test"
        };
        Assert.True(store.Apply(env));
        return new ContentScanner(store);
    }

    [Fact]
    public void DetectsNationalIdAndMasksSample()
    {
        var sc = Build(new { id = "NID", type = "builtin", detector = "tw_national_id", minMatches = 1, severity = "high", action = "alert" });
        var hits = sc.Scan("客戶身分證 A123456789，另一個無效 A123456788");
        var h = Assert.Single(hits);
        Assert.Equal("NID", h.RuleId);
        Assert.Equal(1, h.Count);
        Assert.DoesNotContain("A123456789", h.Sample);
    }

    [Fact]
    public void MinMatchesIsRespected()
    {
        var sc = Build(new { id = "MOB", type = "builtin", detector = "tw_mobile", minMatches = 3 });
        Assert.Empty(sc.Scan("0912-345-678 0922333444"));
        Assert.Single(sc.Scan("0912-345-678 0922333444 0933 555 666"));
    }

    [Fact]
    public void KeywordsAreCaseInsensitive()
    {
        var sc = Build(new { id = "KW", type = "keywords", keywords = new[] { "confidential", "機密" } });
        var h = Assert.Single(sc.Scan("This is CONFIDENTIAL. 本文件為機密。"));
        Assert.Equal(2, h.Count);
    }

    [Fact]
    public void CustomRegexWorksAndBadRegexIsSkipped()
    {
        var sc = Build(
            new { id = "PRJ", type = "regex", pattern = @"PRJ-\d{4}" },
            new { id = "BAD", type = "regex", pattern = "(" });
        var hits = sc.Scan("ticket PRJ-1234 and PRJ-9999");
        var h = Assert.Single(hits);
        Assert.Equal("PRJ", h.RuleId);
        Assert.Equal(2, h.Count);
    }

    [Fact]
    public void DetectsSecrets()
    {
        var sc = Build(
            new { id = "API", type = "builtin", detector = "api_key" },
            new { id = "PK", type = "builtin", detector = "private_key" });
        var hits = sc.Scan("aws_key = AKIAIOSFODNN7EXAMPLE\n-----BEGIN RSA PRIVATE KEY-----\nMIIE...");
        Assert.Contains(hits, h => h.RuleId == "API");
        Assert.Contains(hits, h => h.RuleId == "PK");
    }

    [Fact]
    public void PassportNeedsContextWord()
    {
        var sc = Build(new { id = "PP", type = "builtin", detector = "tw_passport" });
        Assert.Empty(sc.Scan("order 312345678"));
        Assert.Single(sc.Scan("護照號碼: 312345678"));
    }

    [Fact]
    public void DetectsUsSsnAndMultilingualPassport()
    {
        var sc = Build(
            new { id = "SSN", type = "builtin", detector = "us_ssn" },
            new { id = "PP", type = "builtin", detector = "passport" });
        var hits = sc.Scan("SSN 123-45-6789 but not 000-12-3456 or 666-12-3456. Reisepass Nr. C01X00T47. 여권 M12345678");
        Assert.Equal(1, Assert.Single(hits, h => h.RuleId == "SSN").Count);
        Assert.Equal(2, Assert.Single(hits, h => h.RuleId == "PP").Count);
    }

    [Fact]
    public void SummaryReportsWorstSeverity()
    {
        var hits = new[]
        {
            new ScanHit("A", "a", "medium", "log", 1, "x"),
            new ScanHit("B", "b", "critical", "alert", 2, "y"),
        };
        Assert.Equal("critical", ContentScanner.WorstSeverity(hits));
        Assert.StartsWith("severity=critical rules=Ax1,Bx2", ContentScanner.Summarize(hits));
    }
}

public class HeuristicTests
{
    [Theory]
    [InlineData(".jpg", "PE_EXECUTABLE", true)]
    [InlineData(".txt", "ZIP_OR_OOXML", true)]
    [InlineData(".docx", "ZIP_OR_OOXML", false)]
    [InlineData(".exe", "PE_EXECUTABLE", false)]
    public void ExtensionMismatch(string ext, string detected, bool expected) =>
        Assert.Equal(expected, new MagicBytesChecker().IsExtensionMismatch(ext, detected));

    [Fact]
    public void MagicBytesDetectsPngAndPe()
    {
        var png = Path.GetTempFileName();
        File.WriteAllBytes(png, new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A });
        var pe = Path.GetTempFileName();
        File.WriteAllBytes(pe, new byte[] { 0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00 });
        var m = new MagicBytesChecker();
        Assert.Equal("PNG", m.DetectFileType(png));
        Assert.Equal("PE_EXECUTABLE", m.DetectFileType(pe));
    }

    [Fact]
    public void EntropyOfRandomBytesIsHigh()
    {
        var f = Path.GetTempFileName();
        var buf = new byte[65536];
        Random.Shared.NextBytes(buf);
        File.WriteAllBytes(f, buf);
        Assert.True(new EntropyAnalyzer().Estimate(f) > 7.5);
        File.WriteAllBytes(f, new byte[65536]); // all zeros
        Assert.True(new EntropyAnalyzer().Estimate(f) < 0.1);
    }
}

public class PolicyStoreTests
{
    [Fact]
    public void ApplyPersistsAndReloads()
    {
        var dir = Path.Combine(Path.GetTempPath(), "opendlp-tests", Guid.NewGuid().ToString("N"));
        var cache = Path.Combine(dir, "policy.json");
        var store = new PolicyStore(cache, Path.Combine(dir, "none.json"));
        var env = new PolicyEnvelope { Version = 42, PolicyJson = """{"rules":[],"usb":{"mode":"block"}}""", Sig = "x" };
        Assert.True(store.Apply(env));
        Assert.Equal(42, store.Current.Version);
        Assert.Equal("block", store.Current.Usb.Mode);

        var again = new PolicyStore(cache, Path.Combine(dir, "none.json"));
        again.LoadFromDisk();
        Assert.Equal(42, again.Current.Version);
    }

    [Fact]
    public void InvalidJsonIsRejected()
    {
        var dir = Path.Combine(Path.GetTempPath(), "opendlp-tests", Guid.NewGuid().ToString("N"));
        var store = new PolicyStore(Path.Combine(dir, "p.json"), Path.Combine(dir, "d.json"));
        Assert.False(store.Apply(new PolicyEnvelope { Version = 1, PolicyJson = "{not json", Sig = "x" }));
    }
}

public class SignatureTests
{
    [Fact]
    public void EcdsaSignatureRoundTrip()
    {
        using var key = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        var data = System.Text.Encoding.UTF8.GetBytes("{\"rules\":[]}");
        var sig = key.SignData(data, System.Security.Cryptography.HashAlgorithmName.SHA256,
            System.Security.Cryptography.DSASignatureFormat.Rfc3279DerSequence);
        var pem = key.ExportSubjectPublicKeyInfoPem();

        using var pub = PolicySignature.LoadPublicKey(pem)!;
        Assert.True(PolicySignature.Verify(pub, data, Convert.ToBase64String(sig)));
        Assert.False(PolicySignature.Verify(pub, System.Text.Encoding.UTF8.GetBytes("{\"rules\":[1]}"), Convert.ToBase64String(sig)));
        Assert.False(PolicySignature.Verify(pub, data, "not-base64!"));
        Assert.False(PolicySignature.Verify(pub, data, null));
    }

    [Fact]
    public void NoPublicKeyMeansNull() => Assert.Null(PolicySignature.LoadPublicKey(""));
}

public class EnrollmentTests
{
    [Fact]
    public void TokenRoundTripsThroughDpapi()
    {
        var path = Path.Combine(Path.GetTempPath(), "opendlp-tests", Guid.NewGuid().ToString("N"), "cred.bin");
        Enrollment.SaveToken(path, "secret-token-123");
        Assert.Equal("secret-token-123", Enrollment.LoadToken(path));
        Assert.NotEqual("secret-token-123", System.Text.Encoding.UTF8.GetString(File.ReadAllBytes(path)));
        File.WriteAllBytes(path, new byte[] { 1, 2, 3 });
        Assert.Null(Enrollment.LoadToken(path));
        Assert.Null(Enrollment.LoadToken(path + ".missing"));
    }
}

public class SharedVectorTests
{
    private static JsonElement Vectors()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "vectors", "detectors.json");
        return JsonDocument.Parse(File.ReadAllText(path)).RootElement;
    }

    [Fact]
    public void ValidatorsMatchSharedVectors()
    {
        var v = Vectors();
        foreach (var c in v.GetProperty("luhn").EnumerateArray())
            Assert.True(ContentScanner.IsValidCard(c[0].GetString()!) == c[1].GetBoolean(), $"luhn {c[0]}");
        foreach (var c in v.GetProperty("tw_national_id").EnumerateArray())
            Assert.True(ContentScanner.IsValidTwNationalId(c[0].GetString()!) == c[1].GetBoolean(), $"twid {c[0]}");
        foreach (var c in v.GetProperty("iban").EnumerateArray())
            Assert.True(ContentScanner.IsValidIban(c[0].GetString()!) == c[1].GetBoolean(), $"iban {c[0]}");
    }

    [Fact]
    public void ScannerMatchesSharedVectors()
    {
        foreach (var c in Vectors().GetProperty("scan").EnumerateArray())
        {
            var dir = Path.Combine(Path.GetTempPath(), "opendlp-tests", Guid.NewGuid().ToString("N"));
            var store = new PolicyStore(Path.Combine(dir, "p.json"), Path.Combine(dir, "none.json"));
            var policyJson = "{\"rules\":" + c.GetProperty("rules").GetRawText() + "}";
            Assert.True(store.Apply(new PolicyEnvelope { Version = 1, PolicyJson = policyJson, Sig = "x" }));
            var hits = new ContentScanner(store).Scan(c.GetProperty("text").GetString()!)
                .ToDictionary(h => h.RuleId, h => h.Count);
            var expect = c.GetProperty("expect").EnumerateObject().ToDictionary(p => p.Name, p => p.Value.GetInt32());
            Assert.True(expect.Count == hits.Count && expect.All(e => hits.TryGetValue(e.Key, out var n) && n == e.Value),
                $"{c.GetProperty("name").GetString()}: expected {JsonSerializer.Serialize(expect)} got {JsonSerializer.Serialize(hits)}");
        }
    }
}

public class ZipAndFingerprintTests
{
    private static string TempDir()
    {
        var d = Path.Combine(Path.GetTempPath(), "opendlp-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(d);
        return d;
    }

    [Fact]
    public void ZipContentsAreScannedIncludingNestedOffice()
    {
        var dir = TempDir();
        var docx = Path.Combine(dir, "inner.docx");
        using (var z = System.IO.Compression.ZipFile.Open(docx, System.IO.Compression.ZipArchiveMode.Create))
            using (var w = new StreamWriter(z.CreateEntry("word/document.xml").Open()))
                w.Write("<w:t>IBAN GB82 WEST 1234 5698 7654 32</w:t>");
        var zip = Path.Combine(dir, "bundle.zip");
        using (var z = System.IO.Compression.ZipFile.Open(zip, System.IO.Compression.ZipArchiveMode.Create))
        {
            using (var w = new StreamWriter(z.CreateEntry("notes/customers.csv").Open())) w.Write("id,card\n1,4111 1111 1111 1111");
            z.CreateEntryFromFile(docx, "docs/inner.docx");
        }
        Assert.True(TextExtractor.IsSupported(zip));
        var text = TextExtractor.Extract(zip, 1_000_000)!;
        Assert.Contains("4111 1111 1111 1111", text);
        Assert.Contains("GB82 WEST 1234 5698 7654 32", text);
    }

    [Fact]
    public void HashesCoverFileAndZipEntries()
    {
        var dir = TempDir();
        var secret = Path.Combine(dir, "plan.txt");
        File.WriteAllText(secret, "merger plan");
        var expected = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(secret))).ToLowerInvariant();
        var zip = Path.Combine(dir, "renamed.zip");
        using (var z = System.IO.Compression.ZipFile.Open(zip, System.IO.Compression.ZipArchiveMode.Create))
            z.CreateEntryFromFile(secret, "totally-harmless.txt");

        Assert.Contains(TextExtractor.Hashes(secret), h => h.Sha256 == expected);
        var inZip = TextExtractor.Hashes(zip).ToList();
        Assert.Contains(inZip, h => h.Sha256 == expected && h.Name == "totally-harmless.txt");
    }

    [Fact]
    public void ContextWindowIsSymmetric()
    {
        var text = new string('x', 100) + "4111" + new string('y', 100);
        Assert.False(ContentScanner.HasContext(text, 100, 4, new[] { "card" }));
        Assert.True(ContentScanner.HasContext("card " + text, 105, 4, new[] { "card" }) == false);
        Assert.True(ContentScanner.HasContext("Card: 4111", 6, 4, new[] { "card" }));
    }
}

public class AiClassifierTests
{
    private sealed class FakeHandler : HttpMessageHandler
    {
        public string Reply = "";
        public string LastBody = "";
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            LastBody = await request.Content!.ReadAsStringAsync(ct);
            return new HttpResponseMessage(System.Net.HttpStatusCode.OK) { Content = new StringContent(Reply) };
        }
    }

    [Fact]
    public async Task ClassifiesViaOllamaApi()
    {
        var h = new FakeHandler { Reply = JsonSerializer.Serialize(new { response = "{\"label\":\"confidential\",\"reason\":\"unreleased Q3 revenue\"}" }) };
        using var ai = new AiClassifier(h);
        var p = new AiPolicy { Enabled = true, Endpoint = "http://ollama.local:11434", Model = "llama3.2:3b", MaxChars = 300 };
        var r = await ai.ClassifyAsync(p, new string('a', 1000) + "SECRET-TAIL", CancellationToken.None);
        Assert.Equal("confidential", r!.Value.Label);
        Assert.Contains("llama3.2:3b", h.LastBody);
        Assert.DoesNotContain("SECRET-TAIL", h.LastBody);   // only the first MaxChars are sent
    }

    [Fact]
    public async Task DisabledOrGarbageMeansNoClassification()
    {
        var h = new FakeHandler { Reply = "{\"response\":\"not json at all\"}" };
        using var ai = new AiClassifier(h);
        Assert.Null(await ai.ClassifyAsync(new AiPolicy { Enabled = false, Endpoint = "http://x" }, "text", CancellationToken.None));
        Assert.Null(await ai.ClassifyAsync(new AiPolicy { Enabled = true, Endpoint = "http://x" }, "text", CancellationToken.None));
        Assert.Null(AiClassifier.Parse("{\"label\":\"top-secret\"}"));
        Assert.Equal("internal", AiClassifier.Parse("{\"label\":\"Internal\",\"reason\":\"memo\"}")!.Value.Label);
    }

    [Fact]
    public async Task RateLimited()
    {
        var h = new FakeHandler { Reply = JsonSerializer.Serialize(new { response = "{\"label\":\"public\"}" }) };
        using var ai = new AiClassifier(h) { MaxCallsPerMinute = 2 };
        var p = new AiPolicy { Enabled = true, Endpoint = "http://x", Model = "m" };
        Assert.NotNull(await ai.ClassifyAsync(p, "a", CancellationToken.None));
        Assert.NotNull(await ai.ClassifyAsync(p, "b", CancellationToken.None));
        Assert.Null(await ai.ClassifyAsync(p, "c", CancellationToken.None));
    }
}
