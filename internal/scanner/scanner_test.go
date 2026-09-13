package scanner

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// goodServer menyajikan semua header keamanan yang benar + cookie sehat.
func goodServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; upgrade-insecure-requests")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
		w.Header().Set("Cache-Control", "no-store")
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "abc", Path: "/",
			Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		w.Write([]byte("<html>aman</html>"))
	}))
	return srv
}

// fakePreloadAPI menyajikan respons preload kalengan.
func fakePreloadAPI(t *testing.T, status string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(hstsAPIResponse{
			Name:   r.URL.Query().Get("domain"),
			Status: status,
		})
	}))
	old := hstsPreloadAPI
	hstsPreloadAPI = srv.URL
	t.Cleanup(func() { hstsPreloadAPI = old })
	return srv
}

// fakePreloadAPIMap menyajikan status preload berbeda per domain.
func fakePreloadAPIMap(t *testing.T, statuses map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dom := r.URL.Query().Get("domain")
		st := statuses[dom]
		if st == "" {
			st = "unknown"
		}
		json.NewEncoder(w).Encode(hstsAPIResponse{Name: dom, Status: st})
	}))
	old := hstsPreloadAPI
	hstsPreloadAPI = srv.URL
	t.Cleanup(func() { hstsPreloadAPI = old })
	return srv
}

func TestCheckPreloadInheritedFromParent(t *testing.T) {
	fakePreloadAPIMap(t, map[string]string{
		"sub.example.com": "unknown",
		"example.com":     "preloaded",
	})

	res := checkPreloadWithInheritance("sub.example.com", 3*time.Second)
	if !res.Preloaded {
		t.Errorf("preload seharusnya diwarisi dari parent: %+v", res)
	}
	if !strings.Contains(res.Note, "example.com") {
		t.Errorf("catatan harus menyebut parent domain: %+v", res)
	}

	// Parent tidak preloaded → hasil tetap unknown.
	fakePreloadAPIMap(t, map[string]string{
		"sub.example.com": "unknown",
		"example.com":     "unknown",
	})
	res = checkPreloadWithInheritance("sub.example.com", 3*time.Second)
	if res.Preloaded {
		t.Errorf("preload seharusnya tetap false: %+v", res)
	}
}

// fakeDoH menyajikan respons DoH kalengan untuk hostname "localhost".
func fakeDoH(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		qtype := r.URL.Query().Get("type")
		ans := []struct {
			Name string `json:"name"`
			Type int    `json:"type"`
			TTL  int    `json:"TTL"`
			Data string `json:"data"`
		}{}
		d := dohResponse{AD: true}
		switch {
		case qtype == "CAA":
			ans = append(ans, struct {
				Name string `json:"name"`
				Type int    `json:"type"`
				TTL  int    `json:"TTL"`
				Data string `json:"data"`
			}{name, 257, 3600, `0 issue "letsencrypt.org"`})
		case qtype == "TXT" && strings.HasPrefix(name, "_dmarc."):
			ans = append(ans, struct {
				Name string `json:"name"`
				Type int    `json:"type"`
				TTL  int    `json:"TTL"`
				Data string `json:"data"`
			}{name, 16, 300, "v=DMARC1; p=reject"})
		case qtype == "TXT":
			ans = append(ans, struct {
				Name string `json:"name"`
				Type int    `json:"type"`
				TTL  int    `json:"TTL"`
				Data string `json:"data"`
			}{name, 16, 300, "v=spf1 -all"})
		}
		d.Answer = ans
		json.NewEncoder(w).Encode(d)
	}))
	old := dohBaseURLs
	dohBaseURLs = []string{srv.URL}
	t.Cleanup(func() { dohBaseURLs = old })
	return srv
}

func TestScanGoodSite(t *testing.T) {
	srv := goodServer(t)
	defer srv.Close()
	fakePreloadAPI(t, "preloaded")
	fakeDoH(t)

	// Pakai hostname "localhost" (bukan 127.0.0.1) agar modul DNS aktif.
	target := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	res := Scan(target, Options{Timeout: 15 * time.Second})

	if res.Meta.Status != StatusOK {
		t.Fatalf("meta.status = %s: %s", res.Meta.Status, res.Meta.Error)
	}
	if res.Clickjacking.Verdict != VerdictProtected {
		t.Errorf("verdict = %s, want protected", res.Clickjacking.Verdict)
	}
	// Headers 60/60, cookies 15/15, TLS 12/15 (chain self-signed httptest),
	// DNS 10/10 (hostname localhost → bukan IP → modul DNS aktif).
	if res.Grade.Breakdown["headers"].Earned != 60 {
		t.Errorf("headers earned = %d, want 60", res.Grade.Breakdown["headers"].Earned)
	}
	if res.Grade.Breakdown["cookies"].Earned != 15 {
		t.Errorf("cookies earned = %d, want 15", res.Grade.Breakdown["cookies"].Earned)
	}
	if res.Grade.Breakdown["tls"].Earned != 12 || res.Grade.Breakdown["tls"].Applicable != 15 {
		t.Errorf("tls = %+v, want 12/15", res.Grade.Breakdown["tls"])
	}
	if res.Grade.Breakdown["dns"].Earned != 10 || res.Grade.Breakdown["dns"].Applicable != 10 {
		t.Errorf("dns = %+v, want 10/10", res.Grade.Breakdown["dns"])
	}
	if res.Grade.Letter != "A+" || res.Grade.Score != 97 {
		t.Errorf("grade = %s (%d), want A+ (97)", res.Grade.Letter, res.Grade.Score)
	}
	if !res.HSTSPreload.Preloaded {
		t.Errorf("preload = %+v, want preloaded", res.HSTSPreload)
	}
	// Cookie sehat → 3 poin, tanpa isu.
	if len(res.Cookies.Items) != 1 || res.Cookies.Items[0].Points() != 3 {
		t.Errorf("cookies = %+v", res.Cookies.Items)
	}
}

func TestScanBadSite(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>polos</html>"))
	}))
	defer srv.Close()
	fakePreloadAPI(t, "preloaded")

	res := Scan(srv.URL, Options{Timeout: 15 * time.Second})
	if res.Meta.Status != StatusOK {
		t.Fatalf("meta.status = %s: %s", res.Meta.Status, res.Meta.Error)
	}
	if res.Clickjacking.Verdict != VerdictVulnerable {
		t.Errorf("verdict = %s, want vulnerable", res.Clickjacking.Verdict)
	}
	// 127.0.0.1 = IP → DNS n/a; TLS probe gagal → hanya https_enforced 0/4.
	if res.Grade.Breakdown["tls"].Applicable != 4 || res.Grade.Breakdown["tls"].Earned != 0 {
		t.Errorf("tls = %+v, want 0/4", res.Grade.Breakdown["tls"])
	}
	if res.Grade.Breakdown["dns"].Applicable != 0 {
		t.Errorf("dns applicable = %d, want 0 (IP → n/a)", res.Grade.Breakdown["dns"].Applicable)
	}
	if res.Grade.Letter != "F" {
		t.Errorf("grade = %s (%d), want F", res.Grade.Letter, res.Grade.Score)
	}
	if res.DNS.Status != StatusNA {
		t.Errorf("dns.status = %s, want n/a", res.DNS.Status)
	}
	foundHTTPS := false
	for _, f := range res.Findings {
		if strings.Contains(f, "does not use HTTPS") {
			foundHTTPS = true
		}
	}
	if !foundHTTPS {
		t.Errorf("finding 'does not use HTTPS' missing: %v", res.Findings)
	}
}

func TestScanPartial(t *testing.T) {
	// Sebagian header saja + cookie lemah → skor deterministik.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000") // tanpa sub/preload → 7/8
		w.Header().Set("Cache-Control", "no-store")
		http.SetCookie(w, &http.Cookie{Name: "a", Value: "1", HttpOnly: true})
		w.Write([]byte("sebagian"))
	}))
	defer srv.Close()
	fakePreloadAPI(t, "unknown")

	target := strings.Replace(srv.URL, "http://", "https://", 1)
	res := Scan(target, Options{Timeout: 15 * time.Second})

	// Headers: xfo 8 + xcto 5 + hsts 6 (tanpa sub/preload) + cache 3 +
	// disclosure 3 + acao 2 = 27/60.
	if res.Grade.Breakdown["headers"].Earned != 27 {
		t.Errorf("headers = %+v, want 27/60", res.Grade.Breakdown["headers"])
	}
	// Cookie: hanya HttpOnly → 1/3 poin → 15*1/3 = 5/15.
	if res.Grade.Breakdown["cookies"].Earned != 5 {
		t.Errorf("cookies = %+v, want 5/15", res.Grade.Breakdown["cookies"])
	}
	// TLS: https 4 + proto 4 + expiry 4 + chain 0 = 12/15; DNS n/a (IP).
	total := 27 + 5 + 12
	applicable := 60 + 15 + 15
	// 44/90 = 48.9 → 49 → D.
	if res.Grade.Letter != "D" || res.Grade.Score != 49 {
		t.Errorf("grade = %s (%d), want D (49); earned %d/%d",
			res.Grade.Letter, res.Grade.Score, total, applicable)
	}
}

func TestScanUnreachable(t *testing.T) {
	res := Scan("https://192.0.2.1/", Options{Timeout: 5 * time.Second})
	if res.Meta.Status != StatusError {
		t.Errorf("meta.status = %s, want error", res.Meta.Status)
	}
	if res.Meta.Error == "" {
		t.Errorf("meta.error kosong")
	}
}

func TestScanJSONRoundTrip(t *testing.T) {
	srv := goodServer(t)
	defer srv.Close()
	fakePreloadAPI(t, "preloaded")

	target := strings.Replace(srv.URL, "http://", "https://", 1)
	res := Scan(target, Options{Timeout: 15 * time.Second})
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back map[string]any
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"meta", "grade", "headers", "clickjacking", "cookies", "tls", "redirects", "dns", "hsts_preload"} {
		if _, ok := back[key]; !ok {
			t.Errorf("kunci %q hilang di JSON", key)
		}
	}
}
