package scanner

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// hstsPreloadAPI is the official hstspreload.org endpoint. Package-level
// variable so tests can replace it with an httptest server.
var hstsPreloadAPI = "https://hstspreload.org/api/v2/status"

// HSTSPreloadResult adalah status preload HSTS sebuah domain.
type HSTSPreloadResult struct {
	Status       string `json:"status"`        // ok | error | n/a
	DomainStatus string `json:"domain_status"` // preloaded | pending | rejected | unknown
	Preloaded    bool   `json:"preloaded"`
	Note         string `json:"note"`
}

type hstsAPIResponse struct {
	Name            string `json:"name"`
	Status          string `json:"status"`
	Bulk            bool   `json:"bulk"`
	PreloadedDomain string `json:"preloadedDomain"`
}

// CheckHSTSPreload menanyakan status preload domain ke hstspreload.org.
// Dipanggil hanya bila header HSTS valid ditemukan.
func CheckHSTSPreload(host string, timeout time.Duration) *HSTSPreloadResult {
	u := hstsPreloadAPI + "?domain=" + url.QueryEscape(host)
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return &HSTSPreloadResult{Status: StatusError, Note: err.Error()}
	}
	req.Header.Set("Accept", "application/json")

	resp, err := (&http.Client{Timeout: timeout}).Do(req)
	if err != nil {
		return &HSTSPreloadResult{Status: StatusError, Note: "Could not reach hstspreload.org: " + err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return &HSTSPreloadResult{
			Status: StatusError,
			Note:   fmt.Sprintf("hstspreload.org API returned status %d", resp.StatusCode),
		}
	}

	var d hstsAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return &HSTSPreloadResult{Status: StatusError, Note: "API response unreadable: " + err.Error()}
	}

	res := &HSTSPreloadResult{Status: StatusOK, DomainStatus: d.Status}
	switch d.Status {
	case "preloaded":
		res.Preloaded = true
		res.Note = "The domain is on the HSTS preload list — browsers enforce HTTPS from the very first visit."
	case "pending":
		res.Note = "There is a pending preload request for this domain."
	case "rejected":
		res.Note = "A preload request for this domain was rejected (usually because the requirements were not met)."
	default:
		res.DomainStatus = "unknown"
		res.Note = "The domain is not on the HSTS preload list."
	}
	return res
}
