package scanner

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// dohBaseURLs: Google primary, Cloudflare fallback. Package-level variable
// so tests can inject httptest servers.
var dohBaseURLs = []string{
	"https://dns.google/resolve",
	"https://cloudflare-dns.com/dns-query",
}

type dohResponse struct {
	Status int  `json:"Status"`
	AD     bool `json:"AD"`
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		TTL  int    `json:"TTL"`
		Data string `json:"data"`
	} `json:"Answer"`
}

// dnsClient is a DNS-over-HTTPS client with provider fallback.
type dnsClient struct {
	baseURLs []string
	timeout  time.Duration
}

// providerName maps a base URL index to a provider name.
func (c *dnsClient) providerName(i int) string {
	u := c.baseURLs[i]
	switch {
	case strings.Contains(u, "cloudflare"):
		return "cloudflare"
	case strings.Contains(u, "google"):
		return "google"
	default:
		return fmt.Sprintf("doh-%d", i)
	}
}

// query sends one DoH request, trying each provider until one succeeds.
func (c *dnsClient) query(name, qtype string) (*dohResponse, string, error) {
	var lastErr error
	for i, base := range c.baseURLs {
		u := base + "?name=" + url.QueryEscape(name) + "&type=" + url.QueryEscape(qtype)
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Accept", "application/dns-json")
		resp, err := (&http.Client{Timeout: c.timeout}).Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = fmt.Errorf("provider %s answered status %d", c.providerName(i), resp.StatusCode)
			continue
		}
		var d dohResponse
		err = json.NewDecoder(resp.Body).Decode(&d)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		return &d, c.providerName(i), nil
	}
	return nil, "", lastErr
}

// DNSCheck is the result of one DNS check.
type DNSCheck struct {
	Status  string   `json:"status"`
	Records []string `json:"records,omitempty"`
	Details string   `json:"details"`
	AD      bool     `json:"ad,omitempty"`
}

// DNSResult is the result of all DNS checks.
type DNSResult struct {
	Status       string              `json:"status"` // ok | partial | error
	Provider     string              `json:"provider"`
	FallbackUsed bool                `json:"fallback_used"`
	Checks       map[string]DNSCheck `json:"checks"`
}

// apexDomain strips the www subdomain and the port.
func apexDomain(host string) string {
	h := host
	if i := strings.LastIndex(h, ":"); i > strings.LastIndex(h, "]") {
		h = h[:i] // strip the port
	}
	return strings.TrimPrefix(strings.ToLower(h), "www.")
}

// parentDomains returns the host followed by its parent domains, walking up
// to maxHops levels and stopping at two labels. Apex-level policies (CAA,
// SPF, DMARC, HSTS preload) are scored through this chain so subdomain
// scans are treated fairly. This is a heuristic — there is no
// public-suffix list.
func parentDomains(host string, maxHops int) []string {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if i := strings.LastIndex(h, ":"); i > strings.LastIndex(h, "]") {
		h = h[:i] // strip the port
	}
	out := []string{h}
	cur := h
	for range maxHops {
		labels := strings.Split(cur, ".")
		if len(labels) <= 2 {
			break
		}
		cur = strings.Join(labels[1:], ".")
		out = append(out, cur)
	}
	return out
}

// scanDNS runs the four checks (DNSSEC, CAA, SPF, DMARC).
func scanDNS(host string, timeout time.Duration) *DNSResult {
	c := &dnsClient{baseURLs: dohBaseURLs, timeout: timeout}
	res := &DNSResult{Checks: map[string]DNSCheck{}}
	apex := apexDomain(host)

	// DNSSEC: the AD flag on an A/AAAA query (we trust the resolver — the DS
	// chain is not walked ourselves).
	res.Checks["dnssec"] = func() DNSCheck {
		d, prov, err := c.query(apex, "A")
		res.Provider = prov
		if err != nil {
			res.Status = StatusError
			return DNSCheck{Status: StatusError, Details: "DNS query failed: " + err.Error()}
		}
		if d.AD {
			return DNSCheck{Status: StatusOK, AD: true, Details: "The resolver marked the response AD (authenticated data) — DNSSEC is active and validated."}
		}
		return DNSCheck{Status: StatusMissing, Details: "The resolver did not mark AD — DNSSEC is inactive or could not be validated."}
	}()

	if res.Status == StatusError {
		return res
	}

	// CAA: RFC 8659 lookups walk up the DNS tree, so check the host first
	// and then its parent domains.
	res.Checks["caa"] = func() DNSCheck {
		var lastErr error
		for _, dom := range parentDomains(host, 2) {
			d, prov, err := c.query(dom, "CAA")
			res.trackProvider(prov)
			if err != nil {
				lastErr = err
				continue
			}
			var recs []string
			noCA := false
			for _, a := range d.Answer {
				if a.Type == 257 {
					recs = append(recs, a.Data)
					if strings.Contains(a.Data, `issue ";"`) {
						noCA = true
					}
				}
			}
			if len(recs) == 0 {
				continue
			}
			where := ""
			if dom != host {
				where = fmt.Sprintf(" (found on the parent domain %s)", dom)
			}
			if noCA {
				return DNSCheck{Status: StatusOK, Records: recs, Details: `CAA issue ";" is set` + where + ` — no CA is allowed to issue certificates.`}
			}
			return DNSCheck{Status: StatusOK, Records: recs, Details: "CAA records restrict which CAs may issue certificates" + where + "."}
		}
		if lastErr != nil {
			res.Status = StatusPartial
			return DNSCheck{Status: StatusError, Details: "CAA query failed: " + lastErr.Error()}
		}
		return DNSCheck{Status: StatusMissing, Details: "No CAA records on the host or its parent domains — any CA can issue certificates for this domain."}
	}()

	// SPF: TXT on the host, then on the parent domains so subdomain scans
	// are credited for an apex-level policy.
	res.Checks["spf"] = func() DNSCheck {
		var lastErr error
		for _, dom := range parentDomains(host, 2) {
			d, prov, err := c.query(dom, "TXT")
			res.trackProvider(prov)
			if err != nil {
				lastErr = err
				continue
			}
			var spfs []string
			for _, a := range d.Answer {
				if strings.HasPrefix(strings.ToLower(a.Data), "v=spf1") {
					spfs = append(spfs, a.Data)
				}
			}
			if len(spfs) == 0 {
				continue
			}
			where := ""
			if dom != host {
				where = fmt.Sprintf(" Record found on the parent domain %s.", dom)
			}
			if len(spfs) > 1 {
				return DNSCheck{Status: StatusWarn, Records: spfs, Details: "Multiple SPF records found — this violates the standard and is often rejected by receivers." + where}
			}
			return DNSCheck{Status: StatusOK, Records: spfs, Details: "An SPF record is present." + where}
		}
		if lastErr != nil {
			res.Status = StatusPartial
			return DNSCheck{Status: StatusError, Details: "SPF query failed: " + lastErr.Error()}
		}
		return DNSCheck{Status: StatusMissing, Details: "No SPF record on the host or its parent domains — the domain can be used for email spoofing."}
	}()

	// DMARC: TXT on _dmarc.<host>, falling back to parent domains (mirrors
	// the organizational-domain fallback of the DMARC specification).
	res.Checks["dmarc"] = func() DNSCheck {
		var lastErr error
		for _, dom := range parentDomains(host, 2) {
			d, prov, err := c.query("_dmarc."+dom, "TXT")
			res.trackProvider(prov)
			if err != nil {
				lastErr = err
				continue
			}
			var recs []string
			for _, a := range d.Answer {
				if strings.HasPrefix(strings.ToLower(a.Data), "v=dmarc1") {
					recs = append(recs, a.Data)
				}
			}
			if len(recs) == 0 {
				continue
			}
			where := ""
			if dom != host {
				where = fmt.Sprintf(" Record found on the parent domain %s.", dom)
			}
			r := recs[0]
			policy := "not specified"
			for _, tok := range strings.Split(r, ";") {
				tok = strings.TrimSpace(tok)
				if strings.HasPrefix(strings.ToLower(tok), "p=") {
					policy = strings.TrimSpace(tok[2:])
				}
			}
			switch strings.ToLower(policy) {
			case "reject":
				return DNSCheck{Status: StatusOK, Records: recs, Details: "DMARC is set to p=reject — forged email is rejected." + where}
			case "quarantine":
				return DNSCheck{Status: StatusWarn, Records: recs, Details: "DMARC p=quarantine — suspicious email goes to spam instead of being rejected." + where}
			case "none":
				return DNSCheck{Status: StatusWarn, Records: recs, Details: "DMARC p=none — monitoring only, no protection." + where}
			default:
				return DNSCheck{Status: StatusWarn, Records: recs, Details: fmt.Sprintf("Unrecognized DMARC policy %q.", policy)}
			}
		}
		if lastErr != nil {
			res.Status = StatusPartial
			return DNSCheck{Status: StatusError, Details: "DMARC query failed: " + lastErr.Error()}
		}
		return DNSCheck{Status: StatusMissing, Details: "No DMARC record on the host or its parent domains — receivers have no policy for rejecting forged email."}
	}()

	if res.Status == "" {
		res.Status = StatusOK
	}
	if res.Provider == "" {
		res.Provider = "unknown"
	}
	return res
}

// trackProvider records the provider in use and its fallback.
func (r *DNSResult) trackProvider(prov string) {
	if r.Provider == "" {
		r.Provider = prov
	}
	if prov == "cloudflare" {
		r.FallbackUsed = true
	}
}
