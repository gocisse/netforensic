package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/gocisse/netforensic/internal/auth"
	"github.com/gocisse/netforensic/internal/models"
)

const (
	lab7 = "../../testdata/Lab-7-TCPIssues.pcapng"
	lab3 = "../../testdata/Lab-3-TCP-Retrans.pcapng"
)

var testAssets = fstest.MapFS{"index.html": {Data: []byte("<!doctype html><title>ui</title>")}, "assets/app.js": {Data: []byte("console.log(1)")}}

// upload builds a multipart request body with one part.
func upload(t *testing.T, field, filename string, content []byte) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	var part io.Writer
	var err error
	if filename == "" {
		part, err = mw.CreateFormField(field)
	} else {
		part, err = mw.CreateFormFile(field, filename)
	}
	require.NoError(t, err)
	_, err = part.Write(content)
	require.NoError(t, err)
	require.NoError(t, mw.Close())
	return &buf, mw.FormDataContentType()
}

func post(t *testing.T, h http.Handler, body io.Reader, contentType string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/analyze", body)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// testAuth returns an auth service on a fresh credentials file, with the
// default admin/admin login and a cheap bcrypt cost.
func testAuth(t *testing.T) *auth.Service {
	t.Helper()
	svc, err := auth.Open(filepath.Join(t.TempDir(), auth.CredentialsFileName), auth.WithBcryptCost(bcrypt.MinCost))
	require.NoError(t, err)
	return svc
}

// authed is newHandler for tests of everything but authentication: requests
// without an Authorization header get a valid token added.
func authed(t *testing.T, assets fs.FS, maxUpload int64) http.Handler {
	t.Helper()
	svc := testAuth(t)
	token, _, err := svc.Login(auth.DefaultUsername, auth.DefaultPassword)
	require.NoError(t, err)
	inner := newHandler(assets, maxUpload, svc)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		inner.ServeHTTP(w, r)
	})
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	return b
}

func assertJSONError(t *testing.T, rec *httptest.ResponseRecorder, status int, contains string) {
	t.Helper()
	assert.Equal(t, status, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	var e errorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &e), rec.Body.String())
	assert.Contains(t, e.Error, contains)
}

func TestAnalyzeUpload(t *testing.T) {
	h := authed(t, testAssets, maxUploadBytes)
	body, ct := upload(t, "file", "Lab-7-TCPIssues.pcapng", readFile(t, lab7))
	rec := post(t, h, body, ct)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))

	var res models.AnalysisResult
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &res))
	assert.Equal(t, "Lab-7-TCPIssues.pcapng", res.FileName, "the client's name, not the temporary path")
	assert.Equal(t, 64, res.TotalPackets)
	assert.Equal(t, 1, res.TotalFlows)
	assert.Equal(t, 80, res.Diagnosis.HealthScore)
	assert.Equal(t, "Connection reset after zero-window stall", res.Diagnosis.PrimaryCause)
	require.NotEmpty(t, res.ProtocolStats, "the protocol distribution is part of the answer")
	assert.Equal(t, "TCP", res.ProtocolStats[0].Protocol)
	assert.Equal(t, 64, res.ProtocolStats[0].Packets)
	assert.Equal(t, 100.0, res.ProtocolStats[0].Percent)
	require.Len(t, res.Issues, 1)
	assert.Equal(t, []string{"TCP", "TLS"}, res.Issues[0].Protocols, "the flow is TCP carrying TLS")
	assert.Equal(t, "ERROR", string(res.Issues[0].Severity))

	require.NotNil(t, res.Metadata, "the pcapng metadata is part of the answer")
	assert.Contains(t, res.Metadata.CaptureTool, "Dumpcap (Wireshark) 3.4.9")
	assert.Equal(t, "Linux 5.10.0-kali3-amd64", res.Metadata.OS)
	require.Len(t, res.Metadata.Interfaces, 1)
	assert.Equal(t, "eth0", res.Metadata.Interfaces[0].Name)
}

func TestAnalyzeUploadMatchesTheCLIResult(t *testing.T) {
	h := authed(t, testAssets, maxUploadBytes)
	body, ct := upload(t, "file", "Lab-3.pcapng", readFile(t, lab3))
	rec := post(t, h, body, ct)
	require.Equal(t, http.StatusOK, rec.Code)

	var res models.AnalysisResult
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &res))
	assert.Equal(t, 202, res.TotalPackets)
	assert.Equal(t, 80, res.Diagnosis.HealthScore)
	assert.Equal(t, "Fast Retransmit (isolated packet loss)", res.Diagnosis.PrimaryCause)
	var titles []string
	for _, is := range res.Issues {
		titles = append(titles, is.Title)
	}
	assert.ElementsMatch(t, []string{"Fast Retransmit", "TCP Retransmissions detected"}, titles)
}

func TestAnalyzeUploadSanitizesTheFileName(t *testing.T) {
	h := authed(t, testAssets, maxUploadBytes)
	body, ct := upload(t, "file", "../../etc/evil.PCAP", readFile(t, lab7))
	rec := post(t, h, body, ct)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var res models.AnalysisResult
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &res))
	assert.Equal(t, "evil.PCAP", res.FileName, "directory parts are dropped; extensions match case-insensitively")
}

func TestAnalyzeRejectsBadRequests(t *testing.T) {
	h := authed(t, testAssets, maxUploadBytes)
	capture := readFile(t, lab7)

	t.Run("wrong method", func(t *testing.T) {
		for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
			req := httptest.NewRequest(m, "/api/analyze", nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			assertJSONError(t, rec, http.StatusMethodNotAllowed, "use POST")
			assert.Equal(t, http.MethodPost, rec.Header().Get("Allow"))
		}
	})
	t.Run("not multipart", func(t *testing.T) {
		rec := post(t, h, strings.NewReader("x=1"), "application/x-www-form-urlencoded")
		assertJSONError(t, rec, http.StatusBadRequest, "multipart/form-data")
		rec = post(t, h, strings.NewReader("x"), "")
		assertJSONError(t, rec, http.StatusBadRequest, "multipart/form-data")
	})
	t.Run("no file field", func(t *testing.T) {
		body, ct := upload(t, "attachment", "a.pcap", capture)
		assertJSONError(t, post(t, h, body, ct), http.StatusBadRequest, `missing form field "file"`)
	})
	t.Run("the field is not a file upload", func(t *testing.T) {
		body, ct := upload(t, "file", "", []byte("plain text"))
		assertJSONError(t, post(t, h, body, ct), http.StatusBadRequest, "must be a file upload")
	})
	t.Run("unsupported extension", func(t *testing.T) {
		for _, name := range []string{"notes.txt", "capture", "capture.pcap.exe", "capture.zip"} {
			body, ct := upload(t, "file", name, capture)
			assertJSONError(t, post(t, h, body, ct), http.StatusBadRequest, "unsupported file type")
		}
	})
	t.Run("not a capture", func(t *testing.T) {
		body, ct := upload(t, "file", "bad.pcap", []byte("this is not a capture file at all"))
		assertJSONError(t, post(t, h, body, ct), http.StatusBadRequest, "not a readable capture")
	})
	t.Run("empty file", func(t *testing.T) {
		body, ct := upload(t, "file", "empty.pcap", nil)
		assertJSONError(t, post(t, h, body, ct), http.StatusBadRequest, "not a readable capture")
	})
	t.Run("too large", func(t *testing.T) {
		small := authed(t, testAssets, 1024)
		body, ct := upload(t, "file", "big.pcapng", capture)
		assertJSONError(t, post(t, small, body, ct), http.StatusRequestEntityTooLarge, "read upload")
	})
	t.Run("truncated multipart body", func(t *testing.T) {
		body, ct := upload(t, "file", "a.pcapng", capture)
		cut := bytes.NewReader(body.Bytes()[:200])
		rec := post(t, h, cut, ct)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	})
}

func pcapBytes(t *testing.T, frames ...[]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := pcapgo.NewWriter(&buf)
	require.NoError(t, w.WriteFileHeader(65535, layers.LinkTypeEthernet))
	for i, f := range frames {
		require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1700000000+int64(i), 0), CaptureLength: len(f), Length: len(f)}, f))
	}
	return buf.Bytes()
}

func lldpFrame() []byte {
	return append([]byte{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e, 0, 1, 2, 3, 4, 5, 0x88, 0xcc}, make([]byte, 30)...)
}

func udpFrame(t *testing.T) []byte {
	t.Helper()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IP{10, 0, 0, 1}, DstIP: net.IP{10, 0, 0, 2}}
	udp := &layers.UDP{SrcPort: 1000, DstPort: 2000}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		&layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4},
		ip, udp, gopacket.Payload([]byte("hi"))))
	return buf.Bytes()
}

func TestAnalyzeReportsCaptureProblemsLikeTheCLI(t *testing.T) {
	h := authed(t, testAssets, maxUploadBytes)

	t.Run("truncated capture is analyzed and flagged", func(t *testing.T) {
		data := readFile(t, lab3)[:60000]
		body, ct := upload(t, "file", "cut.pcapng", data)
		rec := post(t, h, body, ct)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var res models.AnalysisResult
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &res))
		assert.Positive(t, res.TotalPackets)
		var titles []string
		for _, is := range res.Issues {
			titles = append(titles, is.Title)
		}
		assert.Contains(t, titles, "Truncated Capture")
	})
	t.Run("skipped frames are noted", func(t *testing.T) {
		body, ct := upload(t, "file", "mixed.pcap", pcapBytes(t, udpFrame(t), lldpFrame(), lldpFrame()))
		rec := post(t, h, body, ct)
		require.Equal(t, http.StatusOK, rec.Code)
		var res models.AnalysisResult
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &res))
		assert.Equal(t, 1, res.TotalPackets)
		require.Len(t, res.Issues, 1)
		assert.Equal(t, "Skipped Frames", res.Issues[0].Title)
		assert.Equal(t, 2, res.Issues[0].Count)
		assert.Equal(t, 100, res.Diagnosis.HealthScore, "an informational note costs nothing")
	})
	t.Run("nothing to analyze is not a health score", func(t *testing.T) {
		body, ct := upload(t, "file", "l2only.pcap", pcapBytes(t, lldpFrame()))
		rec := post(t, h, body, ct)
		require.Equal(t, http.StatusOK, rec.Code)
		var got map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
		assert.Equal(t, "l2only.pcap", got["file_name"])
		assert.Equal(t, float64(0), got["total_packets"])
		assert.Equal(t, "The capture contains no analyzable packets", got["message"])
		assert.NotContains(t, got, "diagnosis")
		issues, _ := got["issues"].([]any)
		assert.Len(t, issues, 1, "the skipped-frames note explains why")

		body, ct = upload(t, "file", "empty.pcap", pcapBytes(t))
		rec = post(t, h, body, ct)
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"issues":[]`, "an array, never null")
	})
}

func TestAnalyzeLeavesNoTemporaryFiles(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	h := authed(t, testAssets, 1<<20)
	capture := readFile(t, lab7)

	cases := []struct {
		name, file string
		content    []byte
		wantStatus int
	}{
		{"success", "ok.pcapng", capture, http.StatusOK},
		{"unreadable capture", "bad.pcap", []byte("garbage garbage garbage garbage"), http.StatusBadRequest},
		{"truncated capture", "cut.pcapng", capture[:5000], http.StatusOK},
		{"bad extension", "x.txt", capture, http.StatusBadRequest},
	}
	for _, c := range cases {
		body, ct := upload(t, "file", c.file, c.content)
		rec := post(t, h, body, ct)
		assert.Equal(t, c.wantStatus, rec.Code, c.name)
	}
	// an upload that is cut off while being stored
	body, ct := upload(t, "file", "a.pcapng", capture)
	assert.Equal(t, http.StatusBadRequest, post(t, h, bytes.NewReader(body.Bytes()[:3000]), ct).Code)
	// and one over the size limit
	assert.Equal(t, http.StatusRequestEntityTooLarge, post(t, authed(t, testAssets, 2000), bytes.NewReader(body.Bytes()), ct).Code)

	entries, err := os.ReadDir(tmp)
	require.NoError(t, err)
	assert.Empty(t, entries, "every temporary file is removed, on success and on failure")
}

func TestAnalyzeUsesAPrivateTemporaryFile(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	body, ct := upload(t, "file", "a.pcapng", readFile(t, lab7))
	req := httptest.NewRequest(http.MethodPost, "/api/analyze", body)
	req.Header.Set("Content-Type", ct)

	mr, err := req.MultipartReader()
	require.NoError(t, err)
	name, path, status, err := receiveUpload(mr)
	require.NoError(t, err)
	defer os.Remove(path)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, "a.pcapng", name)
	assert.Equal(t, tmp, filepath.Dir(path))
	assert.Equal(t, ".pcapng", filepath.Ext(path))
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "not readable by other users")
	assert.NotContains(t, path, "a.pcapng", "the client's name is not part of the path")
}

func TestStaticFiles(t *testing.T) {
	h := authed(t, testAssets, maxUploadBytes)
	get := func(h http.Handler, path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec
	}

	rec := get(h, "/")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "<title>ui</title>")
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))

	rec = get(h, "/assets/app.js")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "console.log(1)", rec.Body.String())

	assert.Equal(t, http.StatusNotFound, get(h, "/nope.js").Code)
	rec = get(h, "/../secret") // the mux cleans the path, so it cannot climb out of the tree
	assert.Equal(t, http.StatusTemporaryRedirect, rec.Code)
	assert.Equal(t, "/secret", rec.Header().Get("Location"))

	t.Run("page routes get the page, so a reload or a pasted link works", func(t *testing.T) {
		for _, p := range []string{"/analysis/0123abcd", "/analysis/0123abcd/tcp", "/analysis/0123abcd/dhcpv6?severity=ERROR", "/secret", "/analysis/x/y/z"} {
			rec := get(h, p)
			assert.Equal(t, http.StatusOK, rec.Code, p)
			assert.Contains(t, rec.Body.String(), "<title>ui</title>", p)
			assert.Contains(t, rec.Header().Get("Content-Type"), "text/html", p)
		}
		// but not for files, which stay 404, nor for the API
		for _, p := range []string{"/nope.js", "/assets/missing.css", "/favicon.ico", "/api/nope", "/api/analysis/x/y.csv"} {
			rec := get(h, p)
			assert.NotContains(t, rec.Body.String(), "<title>ui</title>", p)
		}
		assert.Equal(t, http.StatusNotFound, get(h, "/api/nope").Code)
		// only GET and HEAD
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/analysis/x", nil))
		assert.NotContains(t, rec.Body.String(), "<title>ui</title>")
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodHead, "/analysis/x/tcp", nil))
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("the frontend has not been built", func(t *testing.T) {
		unbuilt := authed(t, fstest.MapFS{".gitkeep": {}}, maxUploadBytes)
		rec := get(unbuilt, "/")
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		assert.Contains(t, rec.Body.String(), "npm run build")
		// the API keeps working without the UI
		body, ct := upload(t, "file", "a.pcapng", readFile(t, lab7))
		assert.Equal(t, http.StatusOK, post(t, unbuilt, body, ct).Code)
	})
}

func TestServeAndGracefulShutdown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, ln, authed(t, testAssets, maxUploadBytes)) }()

	base := "http://" + ln.Addr().String()
	resp, err := http.Get(base + "/")
	require.NoError(t, err)
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(b), "<title>ui</title>")

	body, ct := upload(t, "file", "Lab-7.pcapng", readFile(t, lab7))
	resp, err = http.Post(base+"/api/analyze", ct, body)
	require.NoError(t, err)
	var res models.AnalysisResult
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&res))
	resp.Body.Close()
	assert.Equal(t, 64, res.TotalPackets)

	cancel()
	select {
	case err := <-done:
		assert.NoError(t, err, "a clean shutdown is not an error")
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down")
	}
	_, err = http.Get(base + "/")
	assert.Error(t, err, "no longer listening")
}

func TestServeReturnsListenerFailures(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	require.NoError(t, ln.Close()) // Serve on a closed listener fails at once
	err = serve(context.Background(), ln, authed(t, testAssets, maxUploadBytes))
	assert.Error(t, err)
}

func TestStartServerRejectsBadAddresses(t *testing.T) {
	for _, addr := range []string{"not an address", "localhost:notaport", ":99999"} {
		err := StartServer(addr, nil)
		require.Error(t, err, addr)
		assert.Contains(t, err.Error(), "listen on")
	}

	// an address that is already taken
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	err = StartServer(ln.Addr().String(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "listen on")
}
