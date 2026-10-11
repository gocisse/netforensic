package server

import (
	"archive/zip"
	"bytes"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/gocisse/netforensic/internal/export"
	"github.com/gocisse/netforensic/internal/filter"
)

// unsafeName matches what is not allowed in the name of a download.
var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// downloadBase makes a safe base name for a download from the name of the
// uploaded capture, which is the client's.
func downloadBase(captureName string) string {
	base := strings.TrimSuffix(filepath.Base(captureName), filepath.Ext(captureName))
	base = strings.Trim(unsafeName.ReplaceAllString(base, "_"), "._-")
	if base == "" {
		return "capture"
	}
	if len(base) > 80 {
		base = base[:80]
	}
	return base
}

// exportCSV answers GET /api/export-csv with the flows, issues and protocol
// distribution of an analysis as CSV, narrowed by the same filters the page
// offers. Parameters:
//
//	analysis   the ID the analysis was given (required)
//	source_ip, dest_ip, port, protocol, severity, category
//	           the filters (see package filter); all optional
//	file       flows, issues or protocols for one CSV; anything else, or
//	           nothing, for a zip of the three
//
// The tables are the ones the CLI's --export-csv writes, built by package
// export.
func (h *handler) exportCSV(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, http.StatusMethodNotAllowed, "use GET")
		return
	}
	q := r.URL.Query()
	id := q.Get("analysis")
	if id == "" {
		writeError(w, http.StatusBadRequest, "the analysis parameter is required: the ID that /api/analyze returned")
		return
	}
	spec, err := filter.Parse(q)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid filter: "+err.Error())
		return
	}
	res, ok := h.analyses.get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "that analysis is no longer available; upload the capture again")
		return
	}

	tables := export.Tables(spec.Apply(res))
	base := downloadBase(res.FileName)
	if spec.Active() {
		base += "_filtered"
	}

	var body bytes.Buffer
	var contentType, filename string
	if one := strings.ToLower(q.Get("file")); one == "flows" || one == "issues" || one == "protocols" {
		idx := map[string]int{"flows": 0, "issues": 1, "protocols": 2}[one]
		if err := tables[idx].Write(&body); err != nil {
			writeError(w, http.StatusInternalServerError, "could not build the CSV")
			return
		}
		contentType, filename = "text/csv; charset=utf-8", base+tables[idx].Suffix
	} else {
		zw := zip.NewWriter(&body)
		for _, t := range tables {
			f, err := zw.Create(base + t.Suffix)
			if err == nil {
				err = t.Write(f)
			}
			if err != nil {
				writeError(w, http.StatusInternalServerError, "could not build the export")
				return
			}
		}
		if err := zw.Close(); err != nil {
			writeError(w, http.StatusInternalServerError, "could not build the export")
			return
		}
		contentType, filename = "application/zip", base+".zip"
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body.Bytes())
}
