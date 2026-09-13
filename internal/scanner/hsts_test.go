package scanner

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func hstsTestServer(t *testing.T, status string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(hstsAPIResponse{
			Name:   r.URL.Query().Get("domain"),
			Status: status,
		})
	}))
	return srv
}

func withHSTSAPI(t *testing.T, srv *httptest.Server) {
	t.Helper()
	old := hstsPreloadAPI
	hstsPreloadAPI = srv.URL
	t.Cleanup(func() { hstsPreloadAPI = old })
}

func TestCheckHSTSPreloadStatuses(t *testing.T) {
	tests := []struct {
		status    string
		preloaded bool
	}{
		{"preloaded", true},
		{"pending", false},
		{"rejected", false},
		{"unknown", false},
	}
	for _, tt := range tests {
		srv := hstsTestServer(t, tt.status)
		withHSTSAPI(t, srv)
		res := CheckHSTSPreload("example.com", 3*time.Second)
		srv.Close()
		if res.Status != StatusOK {
			t.Errorf("%s: status = %s (%s)", tt.status, res.Status, res.Note)
			continue
		}
		if res.Preloaded != tt.preloaded {
			t.Errorf("%s: preloaded = %v, want %v", tt.status, res.Preloaded, tt.preloaded)
		}
		if res.Note == "" {
			t.Errorf("%s: note kosong", tt.status)
		}
	}
}

func TestCheckHSTSPreloadServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	withHSTSAPI(t, srv)

	res := CheckHSTSPreload("example.com", 3*time.Second)
	if res.Status != StatusError {
		t.Errorf("status = %s, want error", res.Status)
	}
}

func TestCheckHSTSPreloadUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close() // server mati
	withHSTSAPI(t, srv)

	res := CheckHSTSPreload("example.com", 2*time.Second)
	if res.Status != StatusError {
		t.Errorf("status = %s, want error", res.Status)
	}
}
