package scanner

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func opts() FetchOptions {
	return FetchOptions{
		Timeout:           10 * time.Second,
		FollowRedirects:   true,
		AllowHTTPFallback: false,
	}
}

func TestFetchChainRedirects(t *testing.T) {
	// /a -> 301 /b -> 302 /c (200, Set-Cookie, header keamanan)
	mux := http.NewServeMux()
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/b")
		w.WriteHeader(http.StatusMovedPermanently)
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/c")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/c", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, "<html>akhir</html>")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, err := FetchChain(srv.URL+"/a", opts())
	if err != nil {
		t.Fatalf("FetchChain: %v", err)
	}
	if len(res.Hops) != 2 {
		t.Fatalf("hops = %d, want 2: %+v", len(res.Hops), res.Hops)
	}
	if res.Hops[0].StatusCode != 301 || res.Hops[0].Location != "/b" {
		t.Errorf("hop 0 salah: %+v", res.Hops[0])
	}
	if res.Hops[1].StatusCode != 302 {
		t.Errorf("hop 1 salah: %+v", res.Hops[1])
	}
	if res.Hops[1].SecurityHeaders["Strict-Transport-Security"] != "max-age=31536000" {
		t.Errorf("security headers per hop hilang: %+v", res.Hops[1].SecurityHeaders)
	}
	if res.FinalStatus != 200 || !strings.Contains(string(res.Body), "akhir") {
		t.Errorf("final salah: %d %q", res.FinalStatus, res.Body)
	}
}

func TestFetchChainHTTPSUpgrade(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fmt.Fprint(w, "https")
	}))
	defer tlsSrv.Close()
	httpsURL := strings.Replace(tlsSrv.URL, "http://", "https://", 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, httpsURL, http.StatusMovedPermanently)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, err := FetchChain(srv.URL, opts())
	if err != nil {
		t.Fatalf("FetchChain: %v", err)
	}
	if !res.HTTPToHTTPS {
		t.Errorf("HTTPToHTTPS tidak terdeteksi: %+v", res.Hops)
	}
	if len(res.Hops) != 1 || !res.Hops[0].SchemeUpgrade {
		t.Errorf("hop upgrade salah: %+v", res.Hops)
	}
	if res.FinalURL != httpsURL {
		t.Errorf("final URL = %s, want %s", res.FinalURL, httpsURL)
	}
}

func TestFetchChainRedirectCap(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// /0 -> /1 -> ... tanpa akhir
		var next int
		if _, err := fmt.Sscanf(r.URL.Path, "/%d", &next); err != nil {
			next = 0
		}
		http.Redirect(w, r, fmt.Sprintf("/%d", next+1), http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, err := FetchChain(srv.URL+"/0", opts())
	if err != nil {
		t.Fatalf("FetchChain: %v", err)
	}
	if !res.Capped {
		t.Errorf("Capped tidak terdeteksi")
	}
	if len(res.Hops) != maxRedirects {
		t.Errorf("hops = %d, want %d", len(res.Hops), maxRedirects)
	}
}

func TestFetchChainLoop(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/b", http.StatusFound)
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/a", http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, err := FetchChain(srv.URL+"/a", opts())
	if err != nil {
		t.Fatalf("FetchChain: %v", err)
	}
	if !res.LoopDetected {
		t.Errorf("loop tidak terdeteksi: %+v", res.Hops)
	}
}

func TestFetchChainNoFollow(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/x", http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	o := opts()
	o.FollowRedirects = false
	res, err := FetchChain(srv.URL, o)
	if err != nil {
		t.Fatalf("FetchChain: %v", err)
	}
	if res.FinalStatus != 302 {
		t.Errorf("final = %d, want 302", res.FinalStatus)
	}
	if len(res.Hops) != 0 {
		t.Errorf("hops = %d, want 0", len(res.Hops))
	}
}

func TestFetchChainSetCookiePerHop(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "lang", Value: "id", Path: "/"})
		http.Redirect(w, r, "/b", http.StatusFound)
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "x", Path: "/", HttpOnly: true})
		fmt.Fprint(w, "ok")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, err := FetchChain(srv.URL+"/a", opts())
	if err != nil {
		t.Fatalf("FetchChain: %v", err)
	}
	if len(res.Hops) != 1 || len(res.Hops[0].SetCookie) != 1 || !strings.HasPrefix(res.Hops[0].SetCookie[0], "lang=") {
		t.Errorf("set-cookie hop 0 salah: %+v", res.Hops[0].SetCookie)
	}
	if len(res.FinalHeader.Values("Set-Cookie")) != 1 {
		t.Errorf("set-cookie final salah: %+v", res.FinalHeader)
	}
}

func TestFetchChainAutoSchemeFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "http only")
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	o := opts()
	o.AllowHTTPFallback = true
	res, err := FetchChain(host, o)
	if err != nil {
		t.Fatalf("FetchChain: %v", err)
	}
	if !strings.HasPrefix(res.FinalURL, "http://") {
		t.Errorf("fallback http gagal: %s", res.FinalURL)
	}
	found := false
	for _, n := range res.Notes {
		if strings.Contains(n, "HTTPS failed") {
			found = true
		}
	}
	if !found {
		t.Errorf("catatan fallback tidak ada: %v", res.Notes)
	}
}

func TestFetchChainInvalidTarget(t *testing.T) {
	for _, target := range []string{"", "ftp://example.com", "https://", "not a url at all"} {
		if _, err := FetchChain(target, opts()); err == nil {
			t.Errorf("target %q seharusnya error", target)
		}
	}
}

func TestFetchChainUnreachable(t *testing.T) {
	o := opts()
	o.Timeout = 2 * time.Second
	if _, err := FetchChain("https://192.0.2.1/", o); err == nil {
		t.Errorf("host unreachable seharusnya error")
	}
}
