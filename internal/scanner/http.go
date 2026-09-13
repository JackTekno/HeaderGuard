package scanner

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

const (
	maxRedirects = 10
	maxBodyBytes = 512 << 10 // 512 KB — enough for meta CSP detection
)

// Hop is one step in a redirect chain (a response that redirects).
type Hop struct {
	Index           int               `json:"index"`
	URL             string            `json:"url"`
	StatusCode      int               `json:"status_code"`
	Location        string            `json:"location,omitempty"`
	SchemeUpgrade   bool              `json:"scheme_upgrade"`
	SecurityHeaders map[string]string `json:"security_headers,omitempty"`
	SetCookie       []string          `json:"set_cookie,omitempty"`
}

// hopSecurityHeaders is the subset of headers recorded per hop.
var hopSecurityHeaders = []string{
	"Content-Security-Policy",
	"Strict-Transport-Security",
	"X-Frame-Options",
	"X-Content-Type-Options",
	"Referrer-Policy",
	"Permissions-Policy",
}

// FetchOptions controls fetch behavior.
type FetchOptions struct {
	Timeout           time.Duration
	FollowRedirects   bool
	AllowHTTPFallback bool // only for scheme-less targets: try https, then http
}

// FetchResult holds the final response plus the redirect chain.
type FetchResult struct {
	FinalURL        string
	FinalStatus     int
	FinalHeader     http.Header
	Body            []byte
	BodyTruncated   bool
	Hops            []Hop
	Capped          bool
	LoopDetected    bool
	SchemeDowngrade bool
	HTTPToHTTPS     bool
	Notes           []string
}

// hopIndex is the index of the next hop (response); the final response uses
// len(hops) so cookies can be attributed per response.
func hopIndex(hops []Hop) int {
	if len(hops) == 0 {
		return 0
	}
	return hops[len(hops)-1].Index + 1
}

// FetchChain fetches the target together with its full redirect chain.
func FetchChain(target string, opts FetchOptions) (*FetchResult, error) {
	t := strings.TrimSpace(target)
	if t == "" {
		return nil, fmt.Errorf("empty target")
	}
	if strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://") {
		u, err := url.Parse(t)
		if err != nil || u.Host == "" {
			return nil, fmt.Errorf("invalid target: %q", target)
		}
		return fetchOnce(t, opts)
	}
	// No scheme given (e.g. example.com or host:port): try HTTPS, then HTTP.
	res, err := fetchOnce("https://"+t, opts)
	if err == nil {
		res.Notes = append(res.Notes, "No scheme given; HTTPS worked.")
		return res, nil
	}
	if opts.AllowHTTPFallback {
		res2, err2 := fetchOnce("http://"+t, opts)
		if err2 == nil {
			res2.Notes = append(res2.Notes, fmt.Sprintf("HTTPS failed (%v); using HTTP instead.", err))
			return res2, nil
		}
		return nil, fmt.Errorf("both HTTPS and HTTP failed: %v | %v", err, err2)
	}
	return nil, fmt.Errorf("HTTPS failed: %v", err)
}

// fetchOnce fetches one absolute URL and follows redirects per the options.
func fetchOnce(target string, opts FetchOptions) (*FetchResult, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	res := &FetchResult{}

	client := &http.Client{
		Timeout: opts.Timeout,
		Jar:     jar,
		Transport: &http.Transport{
			// InsecureSkipVerify is intentionally enabled for the fetch: sites with
			// bad certificates can still have their headers read. Certificate trust is
			// assessed separately by the TLS module (verified handshake).
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			Proxy:           http.ProxyFromEnvironment,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !opts.FollowRedirects {
				return http.ErrUseLastResponse
			}
			if len(via) > maxRedirects {
				res.Capped = true
				return http.ErrUseLastResponse
			}
			prevResp := req.Response
			prevURL := via[len(via)-1].URL
			// Loop detection: a new URL that was already visited.
			nextKey := req.URL.Scheme + "://" + req.URL.Host + req.URL.Path
			prevKey := prevURL.Scheme + "://" + prevURL.Host + prevURL.Path
			if nextKey == prevKey || res.visited(nextKey) {
				res.LoopDetected = true
				return http.ErrUseLastResponse
			}

			hop := Hop{
				Index:      hopIndex(res.Hops),
				URL:        prevURL.String(),
				StatusCode: prevResp.StatusCode,
				Location:   prevResp.Header.Get("Location"),
			}
			hop.SchemeUpgrade = prevURL.Scheme == "http" && req.URL.Scheme == "https"
			if req.URL.Scheme == "http" && prevURL.Scheme == "https" {
				res.SchemeDowngrade = true
			}
			if hop.SchemeUpgrade {
				res.HTTPToHTTPS = true
			}
			hop.SecurityHeaders = map[string]string{}
			for _, name := range hopSecurityHeaders {
				if v := prevResp.Header.Get(name); v != "" {
					hop.SecurityHeaders[name] = v
				}
			}
			if sc := prevResp.Header.Values("Set-Cookie"); len(sc) > 0 {
				hop.SetCookie = sc
			}
			res.Hops = append(res.Hops, hop)
			return nil
		},
	}

	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "HeaderGuard/1.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Initial vs final scheme (to detect an upgrade on the final response,
	// e.g. an http:// site that 301s straight to https://).
	if resp.Request.URL != nil {
		finalURL := resp.Request.URL.String()
		if strings.HasPrefix(target, "http://") && strings.HasPrefix(finalURL, "https://") {
			res.HTTPToHTTPS = true
		}
		if strings.HasPrefix(target, "https://") && strings.HasPrefix(finalURL, "http://") {
			res.SchemeDowngrade = true
		}
	}

	res.FinalURL = resp.Request.URL.String()
	res.FinalStatus = resp.StatusCode
	res.FinalHeader = resp.Header.Clone()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		// The body failed to read — headers can still be analyzed.
		res.Notes = append(res.Notes, fmt.Sprintf("Could not read the response body: %v", err))
	} else {
		if len(body) > maxBodyBytes {
			res.Body = body[:maxBodyBytes]
			res.BodyTruncated = true
		} else {
			res.Body = body
		}
	}
	return res, nil
}

// visited reports whether the URL appeared as a previous hop.
func (r *FetchResult) visited(key string) bool {
	for _, h := range r.Hops {
		u, err := url.Parse(h.URL)
		if err != nil {
			continue
		}
		if u.Scheme+"://"+u.Host+u.Path == key {
			return true
		}
	}
	return false
}
