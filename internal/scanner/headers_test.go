package scanner

import (
	"net/http"
	"strings"
	"testing"
)

func TestParseHSTS(t *testing.T) {
	tests := []struct {
		in        string
		maxAge    int64
		hasMaxAge bool
		sub       bool
		pre       bool
	}{
		{"max-age=31536000; includeSubDomains; preload", 31536000, true, true, true},
		{"max-age=63072000", 63072000, true, false, false},
		{"max-age=0", 0, true, false, false},
		{"includeSubDomains", 0, false, true, false},
		{"MAX-AGE=86400; INCLUDESUBDOMAINS", 86400, true, true, false},
		{"max-age=abc", 0, false, false, false},
	}
	for _, tt := range tests {
		ma, has, sub, pre := parseHSTS(tt.in)
		if ma != tt.maxAge || has != tt.hasMaxAge || sub != tt.sub || pre != tt.pre {
			t.Errorf("parseHSTS(%q) = (%d,%v,%v,%v), want (%d,%v,%v,%v)",
				tt.in, ma, has, sub, pre, tt.maxAge, tt.hasMaxAge, tt.sub, tt.pre)
		}
	}
}

func TestParseCSPCombines(t *testing.T) {
	dirs := parseCSP([]string{"default-src 'self'; frame-ancestors 'none'", "object-src 'none'; base-uri 'self'"})
	if !containsToken(dirs["frame-ancestors"], "'none'") {
		t.Errorf("frame-ancestors tidak terparse: %v", dirs)
	}
	if !containsToken(dirs["default-src"], "'self'") {
		t.Errorf("default-src tidak terparse: %v", dirs)
	}
	if !containsToken(dirs["object-src"], "'none'") {
		t.Errorf("object-src tidak terparse: %v", dirs)
	}
	if _, ok := dirs["base-uri"]; !ok {
		t.Errorf("base-uri tidak terparse: %v", dirs)
	}
}

func TestParseSetCookie(t *testing.T) {
	// Cookie lengkap dan sehat.
	c := parseSetCookie("sid=abc; Path=/; Secure; HttpOnly; SameSite=Strict", 0, "https")
	if c.Status != StatusOK || len(c.Issues) > 0 {
		t.Errorf("cookie sehat salah ditandai: %+v", c)
	}
	if !c.Secure || !c.HTTPOnly || c.SameSite != "Strict" || c.Path != "/" {
		t.Errorf("atribut salah terparse: %+v", c)
	}
	if c.Points() != 3 {
		t.Errorf("Points() = %d, want 3", c.Points())
	}

	// SameSite=None tanpa Secure = fatal.
	c = parseSetCookie("sid=abc; SameSite=None", 0, "https")
	if c.Status != StatusWarn {
		t.Errorf("status = %s, want warn", c.Status)
	}
	joined := strings.Join(c.Issues, " | ")
	if !strings.Contains(joined, "SameSite=None without Secure") {
		t.Errorf("isu fatal tidak muncul: %v", c.Issues)
	}
	if c.Points() != 0 {
		t.Errorf("Points() = %d, want 0", c.Points())
	}

	// Atribut huruf besar + tanpa HttpOnly.
	c = parseSetCookie("a=1; SECURE; HTTPONLY; SAMESITE=Lax", 0, "http")
	if !c.Secure || !c.HTTPOnly || c.SameSite != "Lax" {
		t.Errorf("atribut case-insensitive gagal: %+v", c)
	}

	// Tanpa SameSite + HTTP (tanpa Secure): 1 isu (hanya SameSite).
	c = parseSetCookie("a=1; HttpOnly", 1, "http")
	if c.Status != StatusWarn || len(c.Issues) != 1 {
		t.Errorf("isu tanpa SameSite salah: %+v", c)
	}

	// SameSite kosong = invalid.
	c = parseSetCookie("a=1; SameSite=", 0, "https")
	joined = strings.Join(c.Issues, " | ")
	if !strings.Contains(joined, "Invalid SameSite") {
		t.Errorf("SameSite kosong tidak terdeteksi: %v", c.Issues)
	}
}

func TestFindMetaCSP(t *testing.T) {
	body := []byte(`<html><head><meta http-equiv="Content-Security-Policy" content="default-src 'self'"></head></html>`)
	if got := findMetaCSP(body); got != "default-src 'self'" {
		t.Errorf("findMetaCSP = %q", got)
	}
	if got := findMetaCSP([]byte("<html><body>tanpa csp</body></html>")); got != "" {
		t.Errorf("findMetaCSP harus kosong, dapat %q", got)
	}
}

func mkHeader(kv map[string]string) http.Header {
	h := http.Header{}
	for k, v := range kv {
		h.Set(k, v)
	}
	return h
}

func findItem(t *testing.T, an *HeaderAnalysis, id string) CheckResult {
	t.Helper()
	for _, it := range an.Items {
		if it.ID == id {
			return it
		}
	}
	t.Fatalf("item %q tidak ditemukan", id)
	return CheckResult{}
}

func TestAnalyzeHeadersPerfect(t *testing.T) {
	h := mkHeader(map[string]string{
		"Content-Security-Policy":      "default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; upgrade-insecure-requests",
		"Strict-Transport-Security":    "max-age=31536000; includeSubDomains; preload",
		"X-Frame-Options":              "DENY",
		"X-Content-Type-Options":       "nosniff",
		"Referrer-Policy":              "strict-origin-when-cross-origin",
		"Permissions-Policy":           "camera=(), microphone=(), geolocation=()",
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
		"Cross-Origin-Embedder-Policy": "require-corp",
		"Cache-Control":                "no-store",
	})
	an := AnalyzeHeaders(h, nil, "https")

	for _, id := range []string{"csp", "hsts", "xfo", "xcto", "referrer-policy", "permissions-policy", "coop", "corp", "coep", "cache-control"} {
		it := findItem(t, an, id)
		if it.Status != StatusOK {
			t.Errorf("%s: status %s (earned %d/%d), want ok — %s", id, it.Status, it.Earned, it.Weight, it.Details)
		}
		if it.Earned != it.Weight {
			t.Errorf("%s: earned %d, want %d", id, it.Earned, it.Weight)
		}
	}
	if it := findItem(t, an, "disclosure"); it.Earned != 3 {
		t.Errorf("disclosure: earned %d, want 3", it.Earned)
	}
	if it := findItem(t, an, "acao"); it.Earned != 2 {
		t.Errorf("acao: earned %d, want 2", it.Earned)
	}
	if an.Clickjack.Verdict != VerdictProtected {
		t.Errorf("verdict = %s, want %s", an.Clickjack.Verdict, VerdictProtected)
	}
	if an.Summary.Earned != an.Summary.Applicable {
		t.Errorf("earned %d != applicable %d", an.Summary.Earned, an.Summary.Applicable)
	}
	if an.Summary.Applicable != 60 {
		t.Errorf("applicable = %d, want 60", an.Summary.Applicable)
	}
}

func TestAnalyzeHeadersEmpty(t *testing.T) {
	an := AnalyzeHeaders(mkHeader(nil), nil, "https")
	// Hanya disclosure (3) dan acao (2) yang mendapat poin — ketidakhadiran
	// keduanya memang kondisi sehat.
	if an.Summary.Earned != 5 {
		t.Errorf("earned = %d, want 5", an.Summary.Earned)
	}
	for _, id := range []string{"csp", "hsts", "xfo", "xcto", "referrer-policy", "permissions-policy", "coop", "corp", "coep", "cache-control"} {
		if it := findItem(t, an, id); it.Status != StatusMissing {
			t.Errorf("%s: status %s, want missing", id, it.Status)
		}
	}
	if an.Clickjack.Verdict != VerdictVulnerable {
		t.Errorf("verdict = %s, want %s", an.Clickjack.Verdict, VerdictVulnerable)
	}
}

func TestAnalyzeHeadersHSTSOnHTTP(t *testing.T) {
	h := mkHeader(map[string]string{"Strict-Transport-Security": "max-age=31536000"})
	an := AnalyzeHeaders(h, nil, "http")
	if it := findItem(t, an, "hsts"); it.Status != StatusNA {
		t.Errorf("hsts di http: status %s, want n/a", it.Status)
	}
	// n/a tidak boleh ikut dihitung.
	if an.Summary.Applicable >= 60 {
		t.Errorf("applicable = %d, hsts n/a seharusnya dikurangi", an.Summary.Applicable)
	}
}

func TestAnalyzeHeadersHSTSEdge(t *testing.T) {
	// max-age pendek.
	h := mkHeader(map[string]string{"Strict-Transport-Security": "max-age=3600"})
	if it := findItem(t, AnalyzeHeaders(h, nil, "https"), "hsts"); it.Earned != 1 || it.Status != StatusWarn {
		t.Errorf("max-age=3600: earned %d status %s, want 1/warn", it.Earned, it.Status)
	}
	// max-age=0.
	h = mkHeader(map[string]string{"Strict-Transport-Security": "max-age=0"})
	if it := findItem(t, AnalyzeHeaders(h, nil, "https"), "hsts"); it.Earned != 0 {
		t.Errorf("max-age=0: earned %d, want 0", it.Earned)
	}
	// Tanpa max-age = invalid.
	h = mkHeader(map[string]string{"Strict-Transport-Security": "includeSubDomains"})
	if it := findItem(t, AnalyzeHeaders(h, nil, "https"), "hsts"); it.Status != StatusWarn || it.Earned != 0 {
		t.Errorf("invalid: earned %d status %s, want 0/warn", it.Earned, it.Status)
	}
	// 6 bulan + sub + preload = 8.
	h = mkHeader(map[string]string{"Strict-Transport-Security": "max-age=15768000; includeSubDomains; preload"})
	if it := findItem(t, AnalyzeHeaders(h, nil, "https"), "hsts"); it.Earned != 8 || it.Status != StatusOK {
		t.Errorf("6 bulan penuh: earned %d status %s, want 8/ok", it.Earned, it.Status)
	}
}

func TestAnalyzeHeadersCSPFrameOnly(t *testing.T) {
	// Hanya frame-ancestors ketat, tanpa XFO.
	h := mkHeader(map[string]string{
		"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
	})
	an := AnalyzeHeaders(h, nil, "https")
	if it := findItem(t, an, "xfo"); it.Earned != 6 || it.Status != StatusOK {
		t.Errorf("xfo via frame-ancestors: earned %d status %s, want 6/ok", it.Earned, it.Status)
	}
	if an.Clickjack.Verdict != VerdictProtected {
		t.Errorf("verdict = %s, want %s", an.Clickjack.Verdict, VerdictProtected)
	}
	// frame-ancestors wildcard = lemah.
	h = mkHeader(map[string]string{
		"Content-Security-Policy": "default-src 'self'; frame-ancestors *",
	})
	an = AnalyzeHeaders(h, nil, "https")
	if it := findItem(t, an, "xfo"); it.Earned != 2 || it.Status != StatusWarn {
		t.Errorf("frame-ancestors *: earned %d status %s, want 2/warn", it.Earned, it.Status)
	}
	if an.Clickjack.Verdict != VerdictWarning {
		t.Errorf("verdict = %s, want %s", an.Clickjack.Verdict, VerdictWarning)
	}
}

func TestAnalyzeHeadersXFOVariants(t *testing.T) {
	// ALLOW-FROM.
	h := mkHeader(map[string]string{"X-Frame-Options": "ALLOW-FROM https://trusted.example"})
	if it := findItem(t, AnalyzeHeaders(h, nil, "https"), "xfo"); it.Earned != 3 || it.Status != StatusWarn {
		t.Errorf("ALLOW-FROM: got %d/%s, want 3/warn", it.Earned, it.Status)
	}
	// Nilai konflik.
	h = mkHeader(map[string]string{"X-Frame-Options": "DENY"})
	h.Add("X-Frame-Options", "SAMEORIGIN")
	if it := findItem(t, AnalyzeHeaders(h, nil, "https"), "xfo"); it.Earned != 2 || it.Status != StatusWarn {
		t.Errorf("konflik: got %d/%s, want 2/warn", it.Earned, it.Status)
	}
	// Nilai tidak dikenal.
	h = mkHeader(map[string]string{"X-Frame-Options": "ASAL"})
	if it := findItem(t, AnalyzeHeaders(h, nil, "https"), "xfo"); it.Earned != 2 || it.Status != StatusWarn {
		t.Errorf("invalid: got %d/%s, want 2/warn", it.Earned, it.Status)
	}
}

func TestAnalyzeHeadersMetaCSPOnly(t *testing.T) {
	h := mkHeader(nil)
	body := []byte(`<meta http-equiv="Content-Security-Policy" content="default-src 'self'">`)
	an := AnalyzeHeaders(h, body, "https")
	if it := findItem(t, an, "csp"); it.Status != StatusWarn || it.Earned != 0 {
		t.Errorf("meta csp: got %s/%d, want warn/0", it.Status, it.Earned)
	}
}

func TestAnalyzeHeadersACAO(t *testing.T) {
	h := mkHeader(map[string]string{"Access-Control-Allow-Origin": "*"})
	if it := findItem(t, AnalyzeHeaders(h, nil, "https"), "acao"); it.Earned != 1 || it.Status != StatusWarn {
		t.Errorf("wildcard: got %d/%s, want 1/warn", it.Earned, it.Status)
	}
	// Wildcard + Set-Cookie.
	h = mkHeader(map[string]string{"Access-Control-Allow-Origin": "*"})
	h.Add("Set-Cookie", "a=1")
	it := findItem(t, AnalyzeHeaders(h, nil, "https"), "acao")
	if !strings.Contains(it.Details, "credentials") {
		t.Errorf("wildcard+credentials not mentioned: %s", it.Details)
	}
	// Origin spesifik.
	h = mkHeader(map[string]string{"Access-Control-Allow-Origin": "https://api.example.com"})
	if it := findItem(t, AnalyzeHeaders(h, nil, "https"), "acao"); it.Earned != 2 || it.Status != StatusOK {
		t.Errorf("spesifik: got %d/%s, want 2/ok", it.Earned, it.Status)
	}
}

func TestAnalyzeHeadersDisclosure(t *testing.T) {
	h := mkHeader(map[string]string{
		"Server":       "Apache/2.4.41 (Ubuntu)",
		"X-Powered-By": "PHP/7.4.3",
	})
	it := findItem(t, AnalyzeHeaders(h, nil, "https"), "disclosure")
	if it.Earned != 1 || it.Status != StatusWarn {
		t.Errorf("got %d/%s, want 1/warn", it.Earned, it.Status)
	}
	if !strings.Contains(it.Details, "Apache/2.4.41") {
		t.Errorf("nilai server tidak disebut: %s", it.Details)
	}
}

func TestParseCookiesMulti(t *testing.T) {
	raw := []string{"sid=1; Secure; HttpOnly; SameSite=Lax", "theme=dark"}
	cs := ParseCookies(raw, 2, "https")
	if len(cs) != 2 {
		t.Fatalf("len = %d, want 2", len(cs))
	}
	if cs[0].SourceHop != 2 || cs[1].SourceHop != 2 {
		t.Errorf("source hop salah: %+v", cs)
	}
	if cs[1].Status != StatusWarn {
		t.Errorf("cookie tanpa flag: status %s, want warn", cs[1].Status)
	}
}
