// Package api provides the HeaderGuard HTTP server (JSON API + web UI).
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jacktekno/headerguard/internal/scanner"
	"github.com/jacktekno/headerguard/internal/ui"
)

const maxBodyBytes = 1 << 20 // 1 MB

// Server handles API requests and web UI assets.
type Server struct {
	scanTimeout time.Duration
}

// NewServer creates a Server with a default scan timeout.
func NewServer(scanTimeout time.Duration) *Server {
	if scanTimeout <= 0 {
		scanTimeout = 30 * time.Second
	}
	return &Server{scanTimeout: scanTimeout}
}

// Handler wires up all routes (Go 1.22 method patterns).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", s.handleHealth)
	mux.HandleFunc("POST /api/scan", s.handleScan)
	mux.Handle("GET /", noCache(ui.Assets()))
	return mux
}

type scanRequest struct {
	Target          string `json:"target"`
	TimeoutSeconds  int    `json:"timeout_seconds"`
	FollowRedirects *bool  `json:"follow_redirects"`
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"version": scanner.Version,
	})
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		writeError(w, http.StatusBadRequest, "unreadable request body")
		return
	}
	var req scanRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if err := validateTarget(req.Target); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	opts := scanner.Options{
		Timeout:           s.scanTimeout,
		FollowRedirects:   true,
		AllowHTTPFallback: true,
	}
	if req.TimeoutSeconds >= 1 && req.TimeoutSeconds <= 120 {
		opts.Timeout = time.Duration(req.TimeoutSeconds) * time.Second
	}
	if req.FollowRedirects != nil {
		opts.FollowRedirects = *req.FollowRedirects
	}

	start := time.Now()
	res := scanner.Scan(req.Target, opts)
	if res.Meta.Status == scanner.StatusOK {
		log.Printf("scan %s -> grade %s (%d/100) in %dms",
			res.Meta.Target, res.Grade.Letter, res.Grade.Score, time.Since(start).Milliseconds())
	} else {
		log.Printf("scan %s -> FAILED: %s", res.Meta.Target, res.Meta.Error)
	}
	writeJSON(w, http.StatusOK, res)
}

// validateTarget rejects clearly invalid input.
func validateTarget(target string) error {
	t := strings.TrimSpace(target)
	if t == "" {
		return fmt.Errorf("target must not be empty")
	}
	u, err := url.Parse(t)
	if err != nil {
		return fmt.Errorf("invalid target")
	}
	if u.Scheme != "" {
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("scheme must be http or https")
		}
		if u.Host == "" {
			return fmt.Errorf("invalid target (empty host)")
		}
	}
	return nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// noCache makes sure browsers do not cache UI assets.
func noCache(fsys fs.FS) http.Handler {
	h := http.FileServerFS(fsys)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		h.ServeHTTP(w, r)
	})
}

// Serve runs the server until SIGINT/SIGTERM, then shuts down gracefully.
// Returns an exit code: 0 on success, 1 on listen failure.
func Serve(addr string, scanTimeout time.Duration) int {
	s := NewServer(scanTimeout)
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	log.Printf("HeaderGuard v%s listening on http://%s", scanner.Version, addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("server error: %v", err)
		return 1
	}
	return 0
}
