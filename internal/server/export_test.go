package server

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/models"
)

// uploadLab analyzes a testdata capture through the handler and returns the
// parsed answer.
func uploadLab(t *testing.T, h http.Handler, path, name string) analysisAnswer {
	t.Helper()
	body, ct := upload(t, "file", name, readFile(t, path))
	rec := post(t, h, body, ct)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var a analysisAnswer
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &a))
	return a
}

// analysisAnswer is what the page reads from an analysis.
type analysisAnswer struct {
	models.AnalysisResult
	Flows []models.Flow `json:"flows"`
}

func get(h http.Handler, path string, params url.Values) *httptest.ResponseRecorder {
	target := path
	if len(params) > 0 {
		target += "?" + params.Encode()
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec
}

func readCSV(t *testing.T, data []byte) [][]string {
	t.Helper()
	rows, err := csv.NewReader(bytes.NewReader(data)).ReadAll()
	require.NoError(t, err)
	return rows
}

func unzip(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	require.NoError(t, err)
	files := map[string][]byte{}
	for _, f := range zr.File {
		rc, err := f.Open()
		require.NoError(t, err)
		b, err := io.ReadAll(rc)
		require.NoError(t, err)
		require.NoError(t, rc.Close())
		files[f.Name] = b
	}
	return files
}

func TestAnalyzeAnswersWithAnIDAndEveryFlow(t *testing.T) {
	h := authed(t, testAssets, maxUploadBytes)
	a := uploadLab(t, h, lab3, "Lab-3.pcapng")
	assert.Len(t, a.AnalysisID, 32, "an unguessable ID")
	assert.Len(t, a.Flows, a.TotalFlows, "every flow, not just the top ones")
	assert.NotEmpty(t, a.Flows)

	other := uploadLab(t, h, lab3, "Lab-3.pcapng")
	assert.NotEqual(t, a.AnalysisID, other.AnalysisID)
}

func TestGetAnalysisReloads(t *testing.T) {
	h := authed(t, testAssets, maxUploadBytes)
	a := uploadLab(t, h, lab7, "Lab-7.pcapng")

	rec := get(h, "/api/analysis/"+a.AnalysisID, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	var again analysisAnswer
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &again))
	assert.Equal(t, a.AnalysisID, again.AnalysisID)
	assert.Equal(t, a.Flows, again.Flows)
	assert.Equal(t, a.Issues, again.Issues)
	assert.Equal(t, a.Diagnosis.HealthScore, again.Diagnosis.HealthScore)

	assertJSONError(t, get(h, "/api/analysis/"+strings.Repeat("0", 32), nil), http.StatusNotFound, "no longer available")
	assertJSONError(t, get(h, "/api/analysis/", nil), http.StatusNotFound, "no longer available")

	req := httptest.NewRequest(http.MethodPost, "/api/analysis/"+a.AnalysisID, nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assertJSONError(t, rec, http.StatusMethodNotAllowed, "use GET")
	assert.Equal(t, "GET", rec.Header().Get("Allow"))
}

func TestExportCSVUnfilteredMatchesTheAnalysis(t *testing.T) {
	h := authed(t, testAssets, maxUploadBytes)
	a := uploadLab(t, h, lab3, "Lab-3.pcapng")

	rec := get(h, "/api/export-csv", url.Values{"analysis": {a.AnalysisID}})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "application/zip", rec.Header().Get("Content-Type"))
	assert.Equal(t, `attachment; filename="Lab-3.zip"`, rec.Header().Get("Content-Disposition"))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))

	files := unzip(t, rec.Body.Bytes())
	require.Len(t, files, 3)
	flows := readCSV(t, files["Lab-3_flows.csv"])
	issues := readCSV(t, files["Lab-3_issues.csv"])
	protocols := readCSV(t, files["Lab-3_protocols.csv"])
	assert.Equal(t, "flow_id", flows[0][0])
	assert.Len(t, flows, 1+a.TotalFlows)
	assert.Len(t, issues, 1+len(a.Issues), "all the issues, notes included, like the CLI")
	assert.Equal(t, []string{"protocol", "layer", "packets", "flows", "percent"}, protocols[0])
	assert.Len(t, protocols, 1+len(a.ProtocolStats))
}

func TestExportCSVFiltered(t *testing.T) {
	h := authed(t, testAssets, maxUploadBytes)
	a := uploadLab(t, h, lab3, "Lab-3.pcapng")
	require.NotEmpty(t, a.Flows)
	require.NotEmpty(t, a.Issues)
	someIP := a.Flows[0].SrcIP
	port := a.Flows[0].DstPort

	t.Run("by IP: only flows with that address, and a _filtered name", func(t *testing.T) {
		rec := get(h, "/api/export-csv", url.Values{"analysis": {a.AnalysisID}, "source_ip": {someIP}, "file": {"flows"}})
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Equal(t, "text/csv; charset=utf-8", rec.Header().Get("Content-Type"))
		assert.Equal(t, `attachment; filename="Lab-3_filtered_flows.csv"`, rec.Header().Get("Content-Disposition"))
		rows := readCSV(t, rec.Body.Bytes())[1:]
		want := 0
		for _, f := range a.Flows {
			if f.SrcIP == someIP || f.DstIP == someIP {
				want++
			}
		}
		assert.Len(t, rows, want)
		for _, r := range rows {
			assert.Contains(t, r[0], someIP)
		}
	})

	t.Run("by severity: only those issues, and no capture notes", func(t *testing.T) {
		rec := get(h, "/api/export-csv", url.Values{"analysis": {a.AnalysisID}, "severity": {"ERROR,WARNING"}, "file": {"issues"}})
		require.Equal(t, http.StatusOK, rec.Code)
		rows := readCSV(t, rec.Body.Bytes())[1:]
		want := 0
		for _, is := range a.Issues {
			if is.Severity == "ERROR" || is.Severity == "WARNING" {
				want++
			}
		}
		assert.Len(t, rows, want)
		for _, r := range rows {
			assert.Contains(t, []string{"ERROR", "WARNING"}, r[1])
		}
	})

	t.Run("by port and protocol: the protocol table is recomputed from the flows", func(t *testing.T) {
		rec := get(h, "/api/export-csv", url.Values{"analysis": {a.AnalysisID}, "port": {strconv.Itoa(int(port))}, "protocol": {"TCP"}, "file": {"protocols"}})
		require.Equal(t, http.StatusOK, rec.Code)
		rows := readCSV(t, rec.Body.Bytes())[1:]
		var tcp []string
		for _, r := range rows {
			if r[0] == "TCP" {
				tcp = r
			}
		}
		require.NotNil(t, tcp)
		var packets int
		for _, f := range a.Flows {
			if (f.SrcPort == port || f.DstPort == port) && f.Protocol == "TCP" {
				packets += f.PacketCount
			}
		}
		assert.Equal(t, strconv.Itoa(packets), tcp[2])
		assert.Equal(t, "100.0", tcp[4], "of the packets that are left")
	})

	t.Run("a filter that matches nothing gives header-only files", func(t *testing.T) {
		rec := get(h, "/api/export-csv", url.Values{"analysis": {a.AnalysisID}, "source_ip": {"192.0.2.99"}})
		require.Equal(t, http.StatusOK, rec.Code)
		for name, data := range unzip(t, rec.Body.Bytes()) {
			assert.Len(t, readCSV(t, data), 1, name)
			assert.True(t, strings.Contains(name, "_filtered_"), name)
		}
	})

	t.Run("all means no filter", func(t *testing.T) {
		rec := get(h, "/api/export-csv", url.Values{"analysis": {a.AnalysisID}, "protocol": {"All"}, "file": {"flows"}})
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Len(t, readCSV(t, rec.Body.Bytes()), 1+a.TotalFlows)
		assert.Contains(t, rec.Header().Get("Content-Disposition"), `"Lab-3_flows.csv"`)
	})
}

func TestExportCSVErrors(t *testing.T) {
	h := authed(t, testAssets, maxUploadBytes)
	a := uploadLab(t, h, lab7, "Lab-7.pcapng")

	tests := []struct {
		name   string
		params url.Values
		status int
		msg    string
	}{
		{"no analysis parameter", url.Values{}, http.StatusBadRequest, "analysis parameter is required"},
		{"an unknown analysis", url.Values{"analysis": {"deadbeef"}}, http.StatusNotFound, "no longer available"},
		{"a bad IP", url.Values{"analysis": {a.AnalysisID}, "source_ip": {"not-an-ip"}}, http.StatusBadRequest, "invalid filter: source_ip"},
		{"a bad port", url.Values{"analysis": {a.AnalysisID}, "port": {"70000"}}, http.StatusBadRequest, "invalid filter: port"},
		{"a backwards port range", url.Values{"analysis": {a.AnalysisID}, "port": {"90-80"}}, http.StatusBadRequest, "runs backwards"},
		{"an unknown severity", url.Values{"analysis": {a.AnalysisID}, "severity": {"FATAL"}}, http.StatusBadRequest, "invalid filter: severity"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertJSONError(t, get(h, "/api/export-csv", tt.params), tt.status, tt.msg)
		})
	}

	t.Run("only GET", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/export-csv?analysis="+a.AnalysisID, nil))
		assertJSONError(t, rec, http.StatusMethodNotAllowed, "use GET")
		assert.Equal(t, "GET", rec.Header().Get("Allow"))
	})
}

func TestExportAndReloadNeedALogin(t *testing.T) {
	env := newAuthEnv(t)
	for _, path := range []string{"/api/export-csv?analysis=x", "/api/analysis/x"} {
		rec := env.do(t, http.MethodGet, path, "", "", nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code, path)
		assert.NotEmpty(t, rec.Header().Get("WWW-Authenticate"), path)
	}
}

func TestDownloadBase(t *testing.T) {
	tests := []struct{ in, want string }{
		{"Lab-7.pcapng", "Lab-7"},
		{"my capture (1).pcap", "my_capture_1"},
		{"../../etc/passwd", "passwd"},
		{`evil"name\r\n.pcap`, "evil_name_r_n"},
		{".pcap", "capture"},
		{"", "capture"},
		{"日本語.pcap", "capture"},
		{strings.Repeat("a", 200) + ".pcap", strings.Repeat("a", 80)},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, downloadBase(tt.in), tt.in)
	}
}

func TestAnalysisStore(t *testing.T) {
	now := time.Unix(1700000000, 0)
	s := newAnalysisStore()
	s.now = func() time.Time { return now }
	s.max = 3
	s.ttl = time.Hour

	res := func(name string) *models.AnalysisResult {
		return &models.AnalysisResult{FileName: name, Flows: []models.Flow{{ID: name, RetransmitEvents: []models.RetransmitEvent{{Seq: 1}}}}}
	}

	a := s.put(res("a"))
	got, ok := s.get(a)
	require.True(t, ok)
	assert.Equal(t, "a", got.FileName)
	assert.Nil(t, got.Flows[0].RetransmitEvents, "the events are not kept")

	_, ok = s.get("nope")
	assert.False(t, ok)

	// the oldest is dropped past the limit
	b, c, d := s.put(res("b")), s.put(res("c")), s.put(res("d"))
	_, ok = s.get(a)
	assert.False(t, ok, "the oldest of four, with room for three")
	for _, id := range []string{b, c, d} {
		_, ok = s.get(id)
		assert.True(t, ok)
	}
	assert.Len(t, s.items, 3)
	assert.Len(t, s.order, 3)

	// analyses expire
	now = now.Add(30 * time.Minute)
	e := s.put(res("e"))
	now = now.Add(45 * time.Minute) // b, c, d are 75 minutes old, e is 45
	_, ok = s.get(b)
	assert.False(t, ok)
	_, ok = s.get(e)
	assert.True(t, ok)
	assert.Len(t, s.items, 1)
	assert.Len(t, s.order, 1)

	// IDs do not repeat
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		id := s.put(res("x"))
		assert.False(t, seen[id])
		seen[id] = true
	}
}
