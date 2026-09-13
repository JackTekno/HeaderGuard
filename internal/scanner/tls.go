package scanner

import (
	"crypto/tls"
	"net"
	"strconv"
	"time"
)

// TLSResult adalah hasil pemeriksaan TLS dan sertifikat.
type TLSResult struct {
	Status         string          `json:"status"` // ok | error
	Error          string          `json:"error,omitempty"`
	HTTPSSupported bool            `json:"https_supported"`
	Protocols      map[string]bool `json:"protocols,omitempty"`
	Cert           *CertInfo       `json:"cert,omitempty"`
}

// CertInfo berisi informasi sertifikat leaf.
type CertInfo struct {
	Subject            string   `json:"subject"`
	Issuer             string   `json:"issuer"`
	NotBefore          string   `json:"not_before"`
	NotAfter           string   `json:"not_after"`
	DaysRemaining      int      `json:"days_remaining"`
	Expired            bool     `json:"expired"`
	NotYetValid        bool     `json:"not_yet_valid"`
	ExpiringSoon       bool     `json:"expiring_soon"`
	SignatureAlgorithm string   `json:"signature_algorithm"`
	SAN                []string `json:"san"`
	ChainValid         bool     `json:"chain_valid"`
	HostnameMatch      bool     `json:"hostname_match"`
	SelfSigned         bool     `json:"self_signed"`
}

// tlsVersions diuji satu per satu (MaxVersion = MinVersion memaksa versi itu).
// Catatan: SSLv3 tidak diuji karena crypto/tls minimal mendukung TLS 1.0.
var tlsVersions = []struct {
	name string
	ver  uint16
}{
	{"TLSv1.3", tls.VersionTLS13},
	{"TLSv1.2", tls.VersionTLS12},
	{"TLSv1.1", tls.VersionTLS11},
	{"TLSv1.0", tls.VersionTLS10},
}

// ProbeTLS memeriksa dukungan TLS, versi protokol, dan sertifikat.
func ProbeTLS(host string, port int, timeout time.Duration) *TLSResult {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	res := &TLSResult{
		Status:         StatusOK,
		HTTPSSupported: false,
		Protocols: map[string]bool{
			"TLSv1.0": false,
			"TLSv1.1": false,
			"TLSv1.2": false,
			"TLSv1.3": false,
		},
	}

	// 1) Verified handshake — the source of truth for certificate info.
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", addr, &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		// Verifikasi gagal — bedakan "sertifikat buruk" (TLS tetap ada)
		// from "TLS is not supported at all".
		conn2, err2 := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", addr, &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		})
		if err2 != nil {
			res.Status = StatusError
			res.Error = "TLS tidak tersedia atau koneksi gagal: " + err2.Error()
			return res
		}
		cs := conn2.ConnectionState()
		res.HTTPSSupported = true
		res.Cert = analyzeCert(&cs, host, time.Now())
		conn2.Close()
	} else {
		cs := conn.ConnectionState()
		res.HTTPSSupported = true
		res.Cert = analyzeCert(&cs, host, time.Now())
		conn.Close()
	}

	// 2) Per-version probes (unverified — only to learn which versions the
	// server accepts).
	probeTimeout := timeout
	if probeTimeout > 3*time.Second {
		probeTimeout = 3 * time.Second
	}
	for _, v := range tlsVersions {
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: probeTimeout}, "tcp", addr, &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         v.ver,
			MaxVersion:         v.ver,
		})
		if err == nil {
			res.Protocols[v.name] = true
			c.Close()
		}
	}
	return res
}

// analyzeCert builds a CertInfo from the connection state.
func analyzeCert(cs *tls.ConnectionState, host string, now time.Time) *CertInfo {
	if len(cs.PeerCertificates) == 0 {
		return nil
	}
	leaf := cs.PeerCertificates[0]
	ci := &CertInfo{
		Subject:            leaf.Subject.String(),
		Issuer:             leaf.Issuer.String(),
		NotBefore:          leaf.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:           leaf.NotAfter.UTC().Format(time.RFC3339),
		DaysRemaining:      int(time.Until(leaf.NotAfter).Hours() / 24),
		SignatureAlgorithm: leaf.SignatureAlgorithm.String(),
		SAN:                leaf.DNSNames,
		ChainValid:         len(cs.VerifiedChains) > 0,
		HostnameMatch:      leaf.VerifyHostname(host) == nil,
		SelfSigned:         len(cs.VerifiedChains) == 0 && leaf.Subject.String() == leaf.Issuer.String(),
	}
	switch {
	case now.After(leaf.NotAfter):
		ci.Expired = true
	case now.Before(leaf.NotBefore):
		ci.NotYetValid = true
	case ci.DaysRemaining <= 30:
		ci.ExpiringSoon = true
	}
	return ci
}
