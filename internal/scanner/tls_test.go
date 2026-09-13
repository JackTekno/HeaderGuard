package scanner

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func serverPort(t *testing.T, srv *httptest.Server) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("alamat server: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	return port
}

func TestProbeTLSSelfSigned(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.StartTLS()
	defer srv.Close()

	// "localhost" tidak ada di SAN cert httptest (example.com + IP local) —
	// dipakai untuk menguji ketidakcocokan hostname.
	res := ProbeTLS("localhost", serverPort(t, srv), 5*time.Second)
	if res.Status != StatusOK {
		t.Fatalf("status = %s (%s), want ok", res.Status, res.Error)
	}
	if !res.HTTPSSupported {
		t.Errorf("https_supported = false")
	}
	// Server Go modern harusnya mendukung TLS 1.2 atau 1.3, bukan 1.0/1.1.
	if !res.Protocols["TLSv1.2"] && !res.Protocols["TLSv1.3"] {
		t.Errorf("TLS 1.2/1.3 tidak terdeteksi: %+v", res.Protocols)
	}
	if res.Protocols["TLSv1.0"] || res.Protocols["TLSv1.1"] {
		t.Errorf("TLS 1.0/1.1 seharusnya tidak aktif: %+v", res.Protocols)
	}
	if res.Cert == nil {
		t.Fatalf("cert nil")
	}
	if res.Cert.ChainValid {
		t.Errorf("sertifikat self-signed httptest seharusnya chain_valid=false")
	}
	if !res.Cert.SelfSigned {
		t.Errorf("self_signed seharusnya true: %+v", res.Cert)
	}
	if res.Cert.HostnameMatch {
		t.Errorf("hostname localhost seharusnya tidak cocok dengan cert httptest: %+v", res.Cert.SAN)
	}
}

func TestProbeTLSNoTLS(t *testing.T) {
	// Server HTTP polos — handshake TLS pasti gagal.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	res := ProbeTLS("127.0.0.1", serverPort(t, srv), 3*time.Second)
	if res.Status != StatusError {
		t.Errorf("status = %s, want error", res.Status)
	}
	if res.HTTPSSupported {
		t.Errorf("https_supported seharusnya false")
	}
}

func TestProbeTLSUnreachable(t *testing.T) {
	res := ProbeTLS("192.0.2.1", 443, 2*time.Second)
	if res.Status != StatusError {
		t.Errorf("status = %s, want error", res.Status)
	}
}

func TestAnalyzeCertExpiring(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.StartTLS()
	defer srv.Close()
	_ = srv
	// Uji hanya logika tanggal pada struct buatan melalui analyzeCert
	// lewat koneksi langsung agar tetap sederhana: pakai cert httptest.
	res := ProbeTLS("127.0.0.1", serverPort(t, srv), 5*time.Second)
	if res.Cert == nil {
		t.Fatalf("cert nil")
	}
	if res.Cert.Expired || res.Cert.NotYetValid {
		t.Errorf("cert httptest seharusnya valid: expired=%v notyet=%v", res.Cert.Expired, res.Cert.NotYetValid)
	}
	if res.Cert.NotBefore == "" || res.Cert.NotAfter == "" || res.Cert.SignatureAlgorithm == "" {
		t.Errorf("field cert kosong: %+v", res.Cert)
	}
}
