package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTestServer(t *testing.T) http.Handler {
	t.Helper()
	return NewServer(10 * time.Second).Handler()
}

func doJSON(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHealth(t *testing.T) {
	rec := doJSON(t, newTestServer(t), http.MethodGet, "/api/health", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	var m map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if m["status"] != "ok" || m["version"] == "" {
		t.Errorf("respons health salah: %v", m)
	}
}

func TestScanBadInput(t *testing.T) {
	h := newTestServer(t)
	tests := []string{
		`{}`,
		`{"target":""}`,
		`{"target":"   "}`,
		`{"target":"ftp://example.com"}`,
		`{"target":"https://"}`,
		`not json`,
	}
	for _, body := range tests {
		rec := doJSON(t, h, http.MethodPost, "/api/scan", body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %q: code = %d, want 400 (%s)", body, rec.Code, rec.Body.String())
		}
	}
}

func TestScanAgainstLocalTarget(t *testing.T) {
	// Target HTTP polos lokal — scan tetap selesai dengan meta.status ok.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Write([]byte("<html>tes</html>"))
	}))
	defer srv.Close()

	h := newTestServer(t)
	rec := doJSON(t, h, http.MethodPost, "/api/scan", `{"target":"`+srv.URL+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	var res map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	for _, key := range []string{"meta", "grade", "headers", "clickjacking", "cookies", "tls", "redirects", "dns", "hsts_preload"} {
		if _, ok := res[key]; !ok {
			t.Errorf("kunci %q hilang di respons", key)
		}
	}
	meta := res["meta"].(map[string]any)
	if meta["status"] != "ok" {
		t.Errorf("meta.status = %v, want ok", meta["status"])
	}
}

func TestScanUnreachableTarget(t *testing.T) {
	h := newTestServer(t)
	rec := doJSON(t, h, http.MethodPost, "/api/scan", `{"target":"https://192.0.2.1/","timeout_seconds":3}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	var res struct {
		Meta struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if res.Meta.Status != "error" || res.Meta.Error == "" {
		t.Errorf("meta = %+v, want status error dengan pesan", res.Meta)
	}
}

func TestStaticServing(t *testing.T) {
	h := newTestServer(t)
	rec := doJSON(t, h, http.MethodGet, "/", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("content-type = %s, want text/html", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("cache-control = %q, want no-cache", cc)
	}
	if !strings.Contains(rec.Body.String(), "HeaderGuard") {
		t.Errorf("body tidak memuat HeaderGuard")
	}
}
