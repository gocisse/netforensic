// Package server serves the embedded web UI and the analysis API over HTTP.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/gocisse/netforensic/internal/analyzer"
	"github.com/gocisse/netforensic/internal/auth"
	"github.com/gocisse/netforensic/internal/models"
	"github.com/gocisse/netforensic/internal/pcap"
	"github.com/gocisse/netforensic/web"
)

const (
	// maxUploadBytes bounds the size of an uploaded capture.
	maxUploadBytes = 512 << 20

	// formFieldName is the multipart field that carries the capture.
	formFieldName = "file"

	shutdownTimeout = 5 * time.Second
)

// StartServer serves the web UI and the analysis API on addr (for example
// ":8080") until the process receives SIGINT or SIGTERM, then shuts down
// gracefully. Logins are checked by authSvc. It returns nil after a clean
// shutdown.
func StartServer(addr string, authSvc *auth.Service) error {
	assets, err := web.Dist()
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %q: %w", addr, err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serve(ctx, ln, newHandler(assets, maxUploadBytes, authSvc))
}

// serve runs handler on ln until ctx is cancelled, then shuts down.
func serve(ctx context.Context, ln net.Listener, handler http.Handler) error {
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Minute, // uploads of large captures take a while
		WriteTimeout:      10 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shut down server: %w", err)
	}
	if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// handler holds the dependencies of the HTTP routes.
type handler struct {
	maxUploadBytes int64
	auth           *auth.Service
	analyses       *analysisStore
}

// newHandler returns the router: the static UI from assets at "/", the login
// API (/api/login, /api/logout, /api/change-password) and the analysis API at
// "/api/analyze", which needs a valid bearer token like /api/change-password,
// as do the endpoints that read the analyses it keeps: /api/analysis/{id} and
// /api/export-csv.
func newHandler(assets fs.FS, maxUpload int64, authSvc *auth.Service) http.Handler {
	h := &handler{maxUploadBytes: maxUpload, auth: authSvc, analyses: newAnalysisStore()}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/login", h.login)
	mux.HandleFunc("/api/logout", h.logout)
	mux.HandleFunc("/api/change-password", h.requireAuth(h.changePassword))
	mux.HandleFunc("/api/analyze", h.requireAuth(h.analyze))
	mux.HandleFunc("/api/analysis/", h.requireAuth(h.getAnalysis))
	mux.HandleFunc("/api/export-csv", h.requireAuth(h.exportCSV))
	mux.Handle("/", staticHandler(assets))
	return securityHeaders(mux)
}

// securityHeaders stops browsers from guessing content types.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

// staticHandler serves assets, or a short hint if the frontend has not been
// built (the embedded directory then holds nothing but a placeholder).
func staticHandler(assets fs.FS) http.Handler {
	if _, err := fs.Stat(assets, "index.html"); err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "The web UI has not been built into this binary. Run \"npm run build\" in web/ and rebuild.", http.StatusServiceUnavailable)
		})
	}
	files := http.FileServer(http.FS(assets))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The page routes in the browser (/analysis/<id>/tcp, ...): a reload or
		// a pasted link asks the server for a path that is no file. Serve the
		// page for those, and let it route; files with an extension and API
		// paths that do not exist stay 404.
		if (r.Method == http.MethodGet || r.Method == http.MethodHead) && isPageRoute(assets, r.URL.Path) {
			r2 := r.Clone(r.Context())
			r2.URL.Path = "/"
			files.ServeHTTP(w, r2)
			return
		}
		files.ServeHTTP(w, r)
	})
}

// isPageRoute reports whether urlPath is a path of the single-page app rather
// than a file or the API: no such file, no extension, not under /api/.
func isPageRoute(assets fs.FS, urlPath string) bool {
	clean := path.Clean("/" + urlPath)
	if clean == "/" || clean == "/api" || strings.HasPrefix(clean, "/api/") || path.Ext(clean) != "" {
		return false
	}
	_, err := fs.Stat(assets, strings.TrimPrefix(clean, "/"))
	return err != nil
}

// errorResponse is the JSON body of every error.
type errorResponse struct {
	Error string `json:"error"`
}

// emptyResult is the JSON body when the capture holds nothing to analyze.
type emptyResult struct {
	FileName     string         `json:"file_name"`
	TotalPackets int            `json:"total_packets"`
	TotalFlows   int            `json:"total_flows"`
	Issues       []models.Issue `json:"issues"`
	Message      string         `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v) // the status is sent; a failed write has nobody to tell
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorResponse{Error: msg})
}

// analyze handles POST /api/analyze: it receives a capture as the multipart
// field "file", analyzes it and answers with the models.AnalysisResult as JSON.
func (h *handler) analyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, http.StatusMethodNotAllowed, "use POST with a multipart form field named \""+formFieldName+"\"")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, h.maxUploadBytes)
	// Stream the upload: parts are copied straight to disk, never held in memory.
	mr, err := r.MultipartReader()
	if err != nil {
		writeError(w, http.StatusBadRequest, "expected a multipart/form-data upload")
		return
	}
	name, tmpPath, status, err := receiveUpload(mr)
	if tmpPath != "" {
		defer os.Remove(tmpPath)
	}
	if err != nil {
		writeError(w, status, err.Error())
		return
	}

	// With ?progress=1 the answer is a stream of JSON lines: a {"stage": ...}
	// line as each step of the analysis starts, then one {"result": ...} line.
	// Without it, the answer is the result alone.
	var progress func(string)
	var send func(v any)
	if r.URL.Query().Get("progress") == "1" {
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Accel-Buffering", "no")
		enc := json.NewEncoder(w)
		flusher, _ := w.(http.Flusher)
		send = func(v any) {
			_ = enc.Encode(v) // a failed write has nobody to tell
			if flusher != nil {
				flusher.Flush()
			}
		}
		progress = func(stage string) { send(progressEvent{Stage: stage}) }
		send(progressEvent{Stage: "reading"})
	}

	fail := func(status int, msg string) {
		if send != nil {
			send(progressEvent{Error: msg, Status: status})
			return
		}
		writeError(w, status, msg)
	}
	done := func(v any) {
		if send != nil {
			send(progressEvent{Result: v})
			return
		}
		writeJSON(w, http.StatusOK, v)
	}

	packets, stats, err := pcap.ReadPacketsStats(tmpPath, pcap.ReadOptions{})
	var truncated *pcap.TruncatedError
	switch {
	case errors.As(err, &truncated):
		// analyze what was read, and say so
	case err != nil && (errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission)):
		fail(http.StatusInternalServerError, "could not read the uploaded file")
		return
	case err != nil:
		fail(http.StatusBadRequest, "not a readable capture: "+err.Error())
		return
	}

	var notes []models.Issue
	if truncated != nil {
		notes = append(notes, analyzer.TruncatedCaptureIssue(packets))
	}
	if stats.Skipped() > 0 {
		notes = append(notes, analyzer.SkippedFramesIssue(stats.Skipped(), stats.Describe(), packets))
	}

	if len(packets) == 0 {
		if notes == nil {
			notes = []models.Issue{}
		}
		done(emptyResult{FileName: name, Issues: notes, Message: "The capture contains no analyzable packets"})
		return
	}

	res := analyzer.AnalyzeWithProgress(packets, "all", progress, notes...)
	res.FileName = name
	res.Metadata = stats.Metadata
	res.AnalysisID = h.analyses.put(res)
	done(analysisResponse{res, res.Flows})
}

// progressEvent is one line of the progress stream of /api/analyze.
type progressEvent struct {
	Stage  string `json:"stage,omitempty"`
	Result any    `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
	Status int    `json:"status,omitempty"`
}

// analysisResponse is the JSON of an analysis as the web UI gets it: the same
// as `-o json`, plus every flow, which the page filters and sums up itself.
type analysisResponse struct {
	*models.AnalysisResult
	Flows []models.Flow `json:"flows"`
}

// getAnalysis answers GET /api/analysis/{id} with an analysis the server still
// holds, so that the page can show it again after a refresh.
func (h *handler) getAnalysis(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, http.StatusMethodNotAllowed, "use GET")
		return
	}
	res, ok := h.analyses.get(strings.TrimPrefix(r.URL.Path, "/api/analysis/"))
	if !ok {
		writeError(w, http.StatusNotFound, "that analysis is no longer available; upload the capture again")
		return
	}
	writeJSON(w, http.StatusOK, analysisResponse{res, res.Flows})
}

// receiveUpload copies the "file" part of the upload into a private
// temporary file (mode 0600, in the system temp directory). It returns the
// client's file name (base name only, never used as a path), the temporary
// path, which the caller must remove, and the HTTP status to use with err.
func receiveUpload(mr *multipart.Reader) (name, tmpPath string, status int, err error) {
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			return "", "", http.StatusBadRequest, fmt.Errorf("missing form field %q: send the capture as a file upload", formFieldName)
		}
		if err != nil {
			return "", "", uploadStatus(err), fmt.Errorf("read upload: %w", err)
		}
		if part.FormName() != formFieldName {
			continue
		}
		if part.FileName() == "" {
			return "", "", http.StatusBadRequest, fmt.Errorf("form field %q must be a file upload", formFieldName)
		}

		name = filepath.Base(part.FileName())
		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".pcap" && ext != ".pcapng" {
			return "", "", http.StatusBadRequest, fmt.Errorf("unsupported file type %q: upload a .pcap or .pcapng file", ext)
		}

		tmp, err := os.CreateTemp("", "netforensic-upload-*"+ext)
		if err != nil {
			return "", "", http.StatusInternalServerError, errors.New("could not store the upload")
		}
		tmpPath = tmp.Name()
		_, copyErr := io.Copy(tmp, part)
		closeErr := tmp.Close()
		if copyErr != nil {
			return "", tmpPath, uploadStatus(copyErr), fmt.Errorf("read upload: %w", copyErr)
		}
		if closeErr != nil {
			return "", tmpPath, http.StatusInternalServerError, errors.New("could not store the upload")
		}
		return name, tmpPath, http.StatusOK, nil
	}
}

// uploadStatus maps a failure while reading the request body to a status.
func uploadStatus(err error) int {
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusBadRequest
}
