package scanner

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// dohTestServer menyajikan respons DoH kalengan berdasarkan name/type.
func dohTestServer(t *testing.T, path string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		qtype := r.URL.Query().Get("type")
		var d dohResponse
		switch {
		case name == "example.com" && qtype == "A":
			d = dohResponse{AD: true}
		case name == "nonsec.example" && qtype == "A":
			d = dohResponse{AD: false}
		case name == "example.com" && qtype == "CAA":
			d = dohResponse{Answer: []struct {
				Name string `json:"name"`
				Type int    `json:"type"`
				TTL  int    `json:"TTL"`
				Data string `json:"data"`
			}{
				{Name: "example.com.", Type: 257, TTL: 3600, Data: `0 issue "letsencrypt.org"`},
			}}
		case name == "spfmulti.example" && qtype == "TXT":
			d = dohResponse{Answer: []struct {
				Name string `json:"name"`
				Type int    `json:"type"`
				TTL  int    `json:"TTL"`
				Data string `json:"data"`
			}{
				{Name: "spfmulti.example.", Type: 16, TTL: 300, Data: "v=spf1 -all"},
				{Name: "spfmulti.example.", Type: 16, TTL: 300, Data: "v=spf1 ~all"},
			}}
		case name == "example.com" && qtype == "TXT":
			d = dohResponse{Answer: []struct {
				Name string `json:"name"`
				Type int    `json:"type"`
				TTL  int    `json:"TTL"`
				Data string `json:"data"`
			}{
				{Name: "example.com.", Type: 16, TTL: 300, Data: "v=spf1 -all"},
			}}
		case name == "_dmarc.example.com" && qtype == "TXT":
			d = dohResponse{Answer: []struct {
				Name string `json:"name"`
				Type int    `json:"type"`
				TTL  int    `json:"TTL"`
				Data string `json:"data"`
			}{
				{Name: "_dmarc.example.com.", Type: 16, TTL: 300, Data: "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"},
			}}
		case name == "_dmarc.example.org" && qtype == "TXT":
			d = dohResponse{Answer: []struct {
				Name string `json:"name"`
				Type int    `json:"type"`
				TTL  int    `json:"TTL"`
				Data string `json:"data"`
			}{
				{Name: "_dmarc.example.org.", Type: 16, TTL: 300, Data: "v=DMARC1; p=none"},
			}}
		}
		json.NewEncoder(w).Encode(d)
	}))
	return srv
}

func withDoH(t *testing.T, srv *httptest.Server) {
	t.Helper()
	old := dohBaseURLs
	dohBaseURLs = []string{srv.URL}
	t.Cleanup(func() { dohBaseURLs = old })
}

func TestScanDNSSecure(t *testing.T) {
	srv := dohTestServer(t, "")
	defer srv.Close()
	withDoH(t, srv)

	res := scanDNS("example.com", 3*time.Second)
	if res.Status != StatusOK {
		t.Fatalf("status = %s, want ok: %+v", res.Status, res)
	}
	if res.Checks["dnssec"].Status != StatusOK || !res.Checks["dnssec"].AD {
		t.Errorf("dnssec salah: %+v", res.Checks["dnssec"])
	}
	if res.Checks["caa"].Status != StatusOK {
		t.Errorf("caa salah: %+v", res.Checks["caa"])
	}
	if !strings.Contains(strings.Join(res.Checks["caa"].Records, " "), "letsencrypt.org") {
		t.Errorf("record CAA hilang: %+v", res.Checks["caa"])
	}
	if res.Checks["spf"].Status != StatusOK {
		t.Errorf("spf salah: %+v", res.Checks["spf"])
	}
	if res.Checks["dmarc"].Status != StatusOK || !strings.Contains(res.Checks["dmarc"].Details, "reject") {
		t.Errorf("dmarc salah: %+v", res.Checks["dmarc"])
	}
	if res.Provider == "" {
		t.Errorf("provider kosong")
	}
}

// dohParentServer: sub.example.com tidak punya record apa pun, example.com
// punya semuanya — dipakai untuk menguji penelusuran parent domain.
func dohParentServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		qtype := r.URL.Query().Get("type")
		var d dohResponse
		switch {
		case name == "example.com" && qtype == "CAA":
			d = dohResponse{Answer: []struct {
				Name string `json:"name"`
				Type int    `json:"type"`
				TTL  int    `json:"TTL"`
				Data string `json:"data"`
			}{
				{Name: "example.com.", Type: 257, TTL: 3600, Data: `0 issue "letsencrypt.org"`},
			}}
		case name == "example.com" && qtype == "TXT":
			d = dohResponse{Answer: []struct {
				Name string `json:"name"`
				Type int    `json:"type"`
				TTL  int    `json:"TTL"`
				Data string `json:"data"`
			}{
				{Name: "example.com.", Type: 16, TTL: 300, Data: "v=spf1 -all"},
			}}
		case name == "_dmarc.example.com" && qtype == "TXT":
			d = dohResponse{Answer: []struct {
				Name string `json:"name"`
				Type int    `json:"type"`
				TTL  int    `json:"TTL"`
				Data string `json:"data"`
			}{
				{Name: "_dmarc.example.com.", Type: 16, TTL: 300, Data: "v=DMARC1; p=reject"},
			}}
		default:
			d = dohResponse{AD: true} // sub.example.com: kosong, AD tetap aktif
		}
		json.NewEncoder(w).Encode(d)
	}))
	return srv
}

func TestScanDNSParentWalk(t *testing.T) {
	srv := dohParentServer(t)
	defer srv.Close()
	withDoH(t, srv)

	res := scanDNS("sub.example.com", 3*time.Second)
	if res.Status != StatusOK {
		t.Fatalf("status = %s, want ok: %+v", res.Status, res)
	}
	// CAA/SPF/DMARC harus ditemukan lewat penelusuran ke parent example.com.
	if res.Checks["caa"].Status != StatusOK || !strings.Contains(res.Checks["caa"].Details, "parent domain example.com") {
		t.Errorf("caa seharusnya ok via parent: %+v", res.Checks["caa"])
	}
	if res.Checks["spf"].Status != StatusOK || !strings.Contains(res.Checks["spf"].Details, "parent domain example.com") {
		t.Errorf("spf seharusnya ok via parent: %+v", res.Checks["spf"])
	}
	if res.Checks["dmarc"].Status != StatusOK || !strings.Contains(res.Checks["dmarc"].Details, "parent domain example.com") {
		t.Errorf("dmarc seharusnya ok via parent: %+v", res.Checks["dmarc"])
	}
	// DNSSEC: AD flag tetap terlihat untuk subdomain dalam zona tertandatangani.
	if res.Checks["dnssec"].Status != StatusOK || !res.Checks["dnssec"].AD {
		t.Errorf("dnssec seharusnya ok: %+v", res.Checks["dnssec"])
	}
}

func TestParentDomains(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"example.com", []string{"example.com"}},
		{"www.example.com", []string{"www.example.com", "example.com"}},
		{"sub.example.com", []string{"sub.example.com", "example.com"}},
		{"a.b.example.com", []string{"a.b.example.com", "b.example.com", "example.com"}},
		// Tanpa public-suffix list, heuristic ini tetap naik sampai "co.uk" —
		// tidak berbahaya, hanya satu query ekstra tanpa hasil.
		{"mail.example.co.uk", []string{"mail.example.co.uk", "example.co.uk", "co.uk"}},
		{"Example.COM.", []string{"example.com"}},
	}
	for _, tt := range tests {
		got := parentDomains(tt.in, 2)
		if strings.Join(got, ",") != strings.Join(tt.want, ",") {
			t.Errorf("parentDomains(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestScanDNSNoRecords(t *testing.T) {
	srv := dohTestServer(t, "")
	defer srv.Close()
	withDoH(t, srv)

	res := scanDNS("example.org", 3*time.Second)
	if res.Checks["dnssec"].Status != StatusMissing {
		t.Errorf("dnssec AD=false seharusnya missing: %+v", res.Checks["dnssec"])
	}
	if res.Checks["caa"].Status != StatusMissing {
		t.Errorf("caa seharusnya missing: %+v", res.Checks["caa"])
	}
	if res.Checks["spf"].Status != StatusMissing {
		t.Errorf("spf seharusnya missing: %+v", res.Checks["spf"])
	}
	if res.Checks["dmarc"].Status != StatusWarn { // p=none
		t.Errorf("dmarc p=none seharusnya warn: %+v", res.Checks["dmarc"])
	}
}

func TestScanDNSSPFMultiple(t *testing.T) {
	srv := dohTestServer(t, "")
	defer srv.Close()
	withDoH(t, srv)

	res := scanDNS("spfmulti.example", 3*time.Second)
	if res.Checks["spf"].Status != StatusWarn {
		t.Errorf("spf ganda seharusnya warn: %+v", res.Checks["spf"])
	}
}

func TestScanDNSFallback(t *testing.T) {
	// Provider pertama rusak (500), kedua sehat.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()
	good := dohTestServer(t, "")
	defer good.Close()

	old := dohBaseURLs
	dohBaseURLs = []string{bad.URL, good.URL + "/cloudflare"}
	t.Cleanup(func() { dohBaseURLs = old })

	res := scanDNS("example.com", 3*time.Second)
	if res.Status != StatusOK {
		t.Fatalf("status = %s, want ok: %+v", res.Status, res)
	}
	if !res.FallbackUsed {
		t.Errorf("fallback_used seharusnya true")
	}
	if res.Provider != "cloudflare" {
		t.Errorf("provider = %s, want cloudflare", res.Provider)
	}
}

func TestScanDNSTotalFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	withDoH(t, srv)

	res := scanDNS("example.com", 3*time.Second)
	if res.Status != StatusError {
		t.Errorf("status = %s, want error", res.Status)
	}
}
