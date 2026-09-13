// Package scanner berisi mesin analisis keamanan web HeaderGuard.
package scanner

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Version adalah versi HeaderGuard.
const Version = "1.0.0"

// Options mengatur satu pemindaian.
type Options struct {
	Timeout           time.Duration // timeout keseluruhan per fase
	FollowRedirects   bool
	AllowHTTPFallback bool // try HTTP when HTTPS fails (scheme-less targets)
}

// Meta adalah metadata hasil scan.
type Meta struct {
	Version    string `json:"version"`
	ScannedAt  string `json:"scanned_at"`
	Target     string `json:"target"`
	FinalURL   string `json:"final_url,omitempty"`
	DurationMs int64  `json:"duration_ms"`
	Status     string `json:"status"` // ok | error
	Error      string `json:"error,omitempty"`
	UserAgent  string `json:"user_agent"`
}

// HeadersModule adalah hasil modul analisis header.
type HeadersModule struct {
	Status  string        `json:"status"`
	Items   []CheckResult `json:"items"`
	Summary HeaderSummary `json:"summary"`
}

// CookiesModule adalah hasil modul analisis cookie.
type CookiesModule struct {
	Status     string        `json:"status"`
	Applicable bool          `json:"applicable"`
	Items      []CookieCheck `json:"items"`
	Fatal      []string      `json:"fatal,omitempty"`
}

// TLSModule adalah hasil modul TLS.
type TLSModule struct {
	Status         string          `json:"status"`
	Error          string          `json:"error,omitempty"`
	HTTPSSupported bool            `json:"https_supported"`
	Protocols      map[string]bool `json:"protocols,omitempty"`
	Cert           *CertInfo       `json:"cert,omitempty"`
}

// RedirectModule adalah hasil modul rantai redirect.
type RedirectModule struct {
	Status          string `json:"status"`
	Followed        bool   `json:"followed"`
	HopCount        int    `json:"hop_count"`
	Capped          bool   `json:"capped"`
	SchemeDowngrade bool   `json:"scheme_downgrade"`
	HTTPToHTTPS     bool   `json:"http_to_https"`
	Hops            []Hop  `json:"hops"`
}

// Result adalah dokumen hasil scan lengkap — satu-satunya sumber data
// for both the web API and the CLI (--json).
type Result struct {
	Meta         Meta                `json:"meta"`
	Grade        Grade               `json:"grade"`
	Headers      HeadersModule       `json:"headers"`
	Clickjacking ClickjackingVerdict `json:"clickjacking"`
	Cookies      CookiesModule       `json:"cookies"`
	TLS          TLSModule           `json:"tls"`
	Redirects    RedirectModule      `json:"redirects"`
	DNS          DNSResult           `json:"dns"`
	HSTSPreload  HSTSPreloadResult   `json:"hsts_preload"`
	Findings     []string            `json:"findings,omitempty"`
	Notes        []string            `json:"notes,omitempty"`
}

// HasFatal menandai cookie dengan kombinasi fatal SameSite=None tanpa Secure.
func (c CookieCheck) HasFatal() bool {
	return strings.ToLower(c.SameSite) == "none" && !c.Secure
}

// subTimeout divides the total timeout among the parallel phases (min 3 s).
func subTimeout(total time.Duration) time.Duration {
	t := total / 3
	if t < 3*time.Second {
		t = 3 * time.Second
	}
	return t
}

// Scan menjalankan pemindaian lengkap terhadap satu target.
// Hanya kegagalan total saat fetch yang membuat scan error; kegagalan
// modul lain diisolasi di dalam hasilnya masing-masing.
func Scan(target string, opts Options) *Result {
	start := time.Now()
	res := &Result{
		Meta: Meta{
			Version:   Version,
			ScannedAt: time.Now().UTC().Format(time.RFC3339),
			Target:    target,
			Status:    StatusOK,
			UserAgent: "HeaderGuard/" + Version,
		},
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 30 * time.Second
	}

	// Fase 1: fetch + rantai redirect (berurutan — host tujuan bergantung
	// on the response).
	fetch, err := FetchChain(target, FetchOptions{
		Timeout:           opts.Timeout,
		FollowRedirects:   opts.FollowRedirects,
		AllowHTTPFallback: opts.AllowHTTPFallback,
	})
	if err != nil {
		res.Meta.Status = StatusError
		res.Meta.Error = err.Error()
		res.Meta.DurationMs = time.Since(start).Milliseconds()
		return res
	}
	res.Meta.FinalURL = fetch.FinalURL
	res.Notes = fetch.Notes

	finalScheme := "http"
	u, _ := url.Parse(fetch.FinalURL)
	if u != nil && u.Scheme != "" {
		finalScheme = u.Scheme
	}

	// Analisis header respons final.
	headerAn := AnalyzeHeaders(fetch.FinalHeader, fetch.Body, finalScheme)
	res.Headers = HeadersModule{Status: StatusOK, Items: headerAn.Items, Summary: headerAn.Summary}
	res.Clickjacking = headerAn.Clickjack

	// Cookie dari seluruh hop + respons final, dedup by nama (hop terakhir
	// wins because it represents the most recent state).
	seen := map[string]int{}
	cookies := []CookieCheck{}
	addCookies := func(list []CookieCheck) {
		for _, c := range list {
			if i, ok := seen[c.Name]; ok {
				cookies[i] = c
				continue
			}
			seen[c.Name] = len(cookies)
			cookies = append(cookies, c)
		}
	}
	for _, hop := range fetch.Hops {
		addCookies(ParseCookies(hop.SetCookie, hop.Index, finalScheme))
	}
	addCookies(ParseCookies(fetch.FinalHeader.Values("Set-Cookie"), hopIndex(fetch.Hops), finalScheme))

	res.Cookies = CookiesModule{Status: StatusOK, Applicable: len(cookies) > 0, Items: cookies}
	for _, c := range cookies {
		if c.HasFatal() {
			res.Cookies.Fatal = append(res.Cookies.Fatal,
				"Cookie \""+c.Name+"\" uses SameSite=None without Secure — browsers reject this cookie.")
			res.Findings = append(res.Findings,
				"Cookie \""+c.Name+"\": SameSite=None without Secure (fatal)")
		}
	}

	// Redirect.
	res.Redirects = RedirectModule{
		Status:          StatusOK,
		Followed:        opts.FollowRedirects,
		HopCount:        len(fetch.Hops),
		Capped:          fetch.Capped,
		SchemeDowngrade: fetch.SchemeDowngrade,
		HTTPToHTTPS:     fetch.HTTPToHTTPS,
		Hops:            fetch.Hops,
	}
	if fetch.Capped {
		res.Findings = append(res.Findings, "The redirect chain hit the 10-hop limit (possible loop).")
	}
	if fetch.SchemeDowngrade {
		res.Findings = append(res.Findings, "Detected an https→http downgrade in the redirect chain.")
	}

	// Host & port tujuan akhir.
	host := "localhost"
	port := 80
	if u != nil && u.Hostname() != "" {
		host = u.Hostname()
	}
	port = 443 // TLS probes default to the standard HTTPS port unless explicit
	if u != nil {
		if p := u.Port(); p != "" {
			port, _ = strconv.Atoi(p)
		} else if u.Scheme == "http" {
			port = 443 // cek apakah HTTPS tersedia di port standar
		}
	}

	// HSTS valid? (dipakai untuk memutuskan kelayakan cek preload)
	hstsValid := false
	for _, it := range headerAn.Items {
		if it.ID == "hsts" && it.Earned > 0 && it.Status != StatusNA {
			hstsValid = true
		}
	}

	// Fase 2: TLS, DNS, dan HSTS preload berjalan paralel.
	sub := subTimeout(opts.Timeout)
	var tlsRes *TLSResult
	var dnsRes *DNSResult
	var preload *HSTSPreloadResult
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		tlsRes = ProbeTLS(host, port, sub)
	}()
	go func() {
		defer wg.Done()
		if net.ParseIP(host) != nil {
			dnsRes = &DNSResult{Status: StatusNA}
			return
		}
		dnsRes = scanDNS(host, sub)
	}()
	go func() {
		defer wg.Done()
		if !hstsValid {
			preload = &HSTSPreloadResult{
				Status: StatusNA,
				Note:   "No valid HSTS header — preload check skipped.",
			}
			return
		}
		preload = checkPreloadWithInheritance(host, sub)
	}()
	wg.Wait()

	res.TLS = TLSModule{Status: tlsRes.Status, Error: tlsRes.Error,
		HTTPSSupported: tlsRes.HTTPSSupported, Protocols: tlsRes.Protocols, Cert: tlsRes.Cert}
	res.DNS = *dnsRes
	res.HSTSPreload = *preload

	// Penilaian.
	res.Grade = computeGrade(res, headerAn, cookies, fetch, tlsRes, dnsRes, preload, finalScheme)
	res.Meta.DurationMs = time.Since(start).Milliseconds()
	return res
}

// checkPreloadWithInheritance checks the host's preload status, then walks
// up to the parent domains when the host itself is not preloaded. Preload
// entries live on the registered domain and subdomains inherit them, so
// this keeps subdomain scans fair.
func checkPreloadWithInheritance(host string, timeout time.Duration) *HSTSPreloadResult {
	res := CheckHSTSPreload(host, timeout)
	if res.Status == StatusOK && !res.Preloaded {
		for _, p := range parentDomains(host, 2)[1:] {
			alt := CheckHSTSPreload(p, timeout)
			if alt.Status == StatusOK && alt.Preloaded {
				alt.Note = fmt.Sprintf("The parent domain %s is on the preload list — subdomains inherit this.", p)
				return alt
			}
		}
	}
	return res
}

// computeGrade merangkai skor tiap kategori menjadi grade akhir dan
// mengumpulkan temuan penting ke res.Findings.
func computeGrade(res *Result, headerAn *HeaderAnalysis, cookies []CookieCheck, fetch *FetchResult,
	tlsRes *TLSResult, dnsRes *DNSResult, preload *HSTSPreloadResult, finalScheme string) Grade {

	in := GradeInput{
		Headers: CategoryScore{Earned: headerAn.Summary.Earned, Applicable: headerAn.Summary.Applicable},
	}

	// Cookies: 15 poin = rata-rata poin per cookie (maks 3) dinormalisasi.
	if len(cookies) > 0 {
		total := 0
		for _, c := range cookies {
			total += c.Points()
		}
		in.Cookies = CategoryScore{
			Earned:     int(15 * float64(total) / float64(3*len(cookies))),
			Applicable: 15,
		}
		for _, c := range cookies {
			if c.HasFatal() {
				in.CookieFatal = true
			}
		}
	}

	// TLS & HTTPS: https_enforced selalu berlaku; sisanya bila TLS tersedia.
	in.TLS.Applicable = 4
	switch {
	case finalScheme == "https":
		in.TLS.Earned += 4
	case fetch.HTTPToHTTPS:
		in.TLS.Earned += 4
	default:
		res.Findings = append(res.Findings, "The site does not use HTTPS (no http→https redirect).")
		if tlsRes.Status == StatusOK && tlsRes.HTTPSSupported {
			res.Findings = append(res.Findings,
				"HTTPS is actually available on port 443, but the site still serves HTTP.")
		}
	}
	if tlsRes.Status == StatusOK && tlsRes.HTTPSSupported {
		in.TLS.Applicable += 4 + 4 + 3

		// Versi protokol (komponen terpisah — tidak mengurangi poin
		// https_enforced).
		protoScore := 0
		switch {
		case tlsRes.Protocols["TLSv1.3"]:
			protoScore = 4
		case tlsRes.Protocols["TLSv1.2"]:
			protoScore = 3
		}
		if tlsRes.Protocols["TLSv1.1"] {
			protoScore--
		}
		if tlsRes.Protocols["TLSv1.0"] {
			protoScore--
		}
		if protoScore < 0 {
			protoScore = 0
		}
		in.TLS.Earned += protoScore
		if tlsRes.Protocols["TLSv1.0"] || tlsRes.Protocols["TLSv1.1"] {
			res.Findings = append(res.Findings,
				"TLS 1.0/1.1 is still supported — obsolete and vulnerable to downgrade attacks.")
		}

		// Certificate.
		if cert := tlsRes.Cert; cert != nil {
			switch {
			case cert.Expired:
				res.Findings = append(res.Findings, "The TLS certificate has expired.")
			case cert.NotYetValid:
				res.Findings = append(res.Findings, "The TLS certificate is not yet valid.")
			case cert.ExpiringSoon:
				in.TLS.Earned += 2
				res.Findings = append(res.Findings,
					"The TLS certificate expires within 30 days.")
			default:
				in.TLS.Earned += 4
			}
			if cert.ChainValid && cert.HostnameMatch {
				in.TLS.Earned += 3
			} else {
				if !cert.ChainValid {
					res.Findings = append(res.Findings,
						"The certificate chain is not verified (self-signed or untrusted CA).")
				}
				if !cert.HostnameMatch {
					res.Findings = append(res.Findings,
						"The hostname does not match the TLS certificate.")
				}
			}
		}
	}

	// DNS & HSTS Preload: 10 poin; cek yang gagal/error tidak dihitung.
	dnsApplicable := 0
	dnsEarned := 0
	if dnsRes.Status == StatusOK || dnsRes.Status == StatusPartial {
		scored := func(name string, okPoints, warnPoints int) {
			ch := dnsRes.Checks[name]
			switch ch.Status {
			case StatusOK:
				dnsApplicable += okPoints
				dnsEarned += okPoints
			case StatusWarn:
				dnsApplicable += okPoints
				dnsEarned += warnPoints
			case StatusMissing:
				dnsApplicable += okPoints
			}
		}
		scored("dnssec", 2, 0)
		scored("caa", 2, 0)
		scored("spf", 2, 1)
		scored("dmarc", 2, 1)

		// Preload (bobot 2) hanya berlaku bila HSTS valid.
		if preload.Status != StatusNA {
			dnsApplicable += 2
			switch preload.DomainStatus {
			case "preloaded":
				dnsEarned += 2
			case "pending":
				dnsEarned += 1
			}
		}
		in.DNS = CategoryScore{Earned: dnsEarned, Applicable: dnsApplicable}
	}

	return ComputeGrade(in)
}
