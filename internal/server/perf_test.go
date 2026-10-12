package server

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLargeCaptureStreamsProgressively uploads a large synthetic capture
// (cmd/gencap: TCP with handshakes, retransmissions, resets and unanswered
// SYNs, DNS with errors, HTTP errors and ICMP, spread over five minutes) and
// checks that the analysis reaches the page in chunks: the verdict first, soon
// after the analysis is stored, then the issues and the flows in batches.
//
// It is skipped with -short, and runs 100,000 packets (about ten seconds)
// unless NETFORENSIC_PERF_PACKETS asks for another size:
//
//	NETFORENSIC_PERF_PACKETS=1500000 go test -run TestLargeCaptureStreamsProgressively -v ./internal/server
//
// Measured on an Apple M-series laptop with 1.5 million packets (115,000
// flows, 171,000 issues, a 307 MB capture), before and after this work. The
// server numbers come from this test's logs and from `./netforensic file`; the
// page numbers from headless Chrome driven over the DevTools protocol.
//
//	                                       before      after
//	analysis done, result starts to flow   48 s        36 s
//	first byte of the result chunks        (one line)  36.5 s (0.03 s after the analysis)
//	health score and cause on screen       82 s        36.7 s
//	all issues and flows loaded            82 s        38.6 s
//	longest block of the page's main thread 11.5 s     0.6 s   (123 blocks, 32 s -> 4 blocks, 1.2 s)
//	server peak RSS                        2.6 GB      2.25 GB
//	CLI run (read + analyze + report)      42.8 s      31.5 s
//	retained analysis in memory            443 MB      284 MB
//
// With a plain Go client instead of the browser (no 600 ms of Chrome upload
// overhead, no rendering) the same capture is stored after 30.5 s, the summary
// chunk follows 28 ms later and the last flow after 1.2 s, on a heap that
// peaks at 2.9 GB including this test's own parsing.
//
// The page waits for the analysis itself (36 s here), which streaming cannot
// shorten: the verdict needs all of the issues. What it removes is the 30 s
// that followed: a 170 MB document held as one string, parsed in one go and
// grouped by an O(n²) loop.
func TestLargeCaptureStreamsProgressively(t *testing.T) {
	if testing.Short() {
		t.Skip("a large capture is analyzed; skipped with -short")
	}
	packets := 100_000
	if v := os.Getenv("NETFORENSIC_PERF_PACKETS"); v != "" {
		n, err := strconv.Atoi(v)
		require.NoError(t, err, "NETFORENSIC_PERF_PACKETS must be a number")
		packets = n
	}

	path := filepath.Join(t.TempDir(), "big.pcap")
	gen := exec.Command("go", "run", "../../cmd/gencap", "-packets", strconv.Itoa(packets), "-duration", "5m", "-out", path)
	if out, err := gen.CombinedOutput(); err != nil {
		t.Fatalf("generating the capture: %v\n%s", err, out)
	}

	srv := httptest.NewServer(authed(t, testAssets, maxUploadBytes))
	defer srv.Close()

	// peak heap of this process, which holds the server
	var peak atomic.Uint64
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(100 * time.Millisecond):
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				if m.HeapAlloc > peak.Load() {
					peak.Store(m.HeapAlloc)
				}
			}
		}
	}()
	defer close(stop)

	// upload, streaming the file; the answer is the stages and the analysis ID
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		part, err := mw.CreateFormFile("file", "big.pcap")
		if err == nil {
			var f *os.File
			if f, err = os.Open(path); err == nil {
				_, err = io.Copy(part, f)
				f.Close()
			}
		}
		if err == nil {
			err = mw.Close()
		}
		pw.CloseWithError(err)
	}()
	start := time.Now()
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/analyze?progress=1&chunked=1", pr)
	require.NoError(t, err)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var id string
	var firstByte time.Duration
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		if firstByte == 0 {
			firstByte = time.Since(start)
		}
		var ev struct {
			AnalysisID string `json:"analysis_id"`
			Error      string `json:"error"`
		}
		require.NoError(t, json.Unmarshal(sc.Bytes(), &ev))
		require.Empty(t, ev.Error)
		if ev.AnalysisID != "" {
			id = ev.AnalysisID
		}
	}
	require.NoError(t, sc.Err())
	require.NotEmpty(t, id)
	analyzed := time.Since(start)

	// fetch the chunks
	getStart := time.Now()
	cresp, err := http.Get(srv.URL + "/api/analysis/" + id + "?chunked=1")
	require.NoError(t, err)
	defer cresp.Body.Close()
	br := bufio.NewReaderSize(cresp.Body, 1<<20)
	var order []string
	var firstChunk, firstIssues, lastChunk time.Duration
	var issues, flows, counted, countedFlows int
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			at := time.Since(getStart)
			var ev struct {
				Chunk string          `json:"chunk"`
				Data  json.RawMessage `json:"data"`
			}
			require.NoError(t, json.Unmarshal(line, &ev))
			if len(order) == 0 || order[len(order)-1] != ev.Chunk {
				order = append(order, ev.Chunk)
			}
			switch ev.Chunk {
			case chunkSummary:
				firstChunk = at
				var s summaryChunk
				require.NoError(t, json.Unmarshal(ev.Data, &s))
				counted, countedFlows = s.Counts.Issues, s.Counts.Flows
			case chunkIssues:
				if firstIssues == 0 {
					firstIssues = at
				}
				var b []json.RawMessage
				require.NoError(t, json.Unmarshal(ev.Data, &b))
				issues += len(b)
			case chunkFlows:
				var b []json.RawMessage
				require.NoError(t, json.Unmarshal(ev.Data, &b))
				flows += len(b)
			}
			lastChunk = at
		}
		if err != nil {
			require.ErrorIs(t, err, io.EOF)
			break
		}
	}

	t.Logf("%d packets: first stage byte %s, analysis stored after %s", packets, firstByte.Round(time.Millisecond), analyzed.Round(time.Millisecond))
	t.Logf("chunks: summary after %s, first issues after %s, all %d issues and %d flows after %s", firstChunk.Round(time.Millisecond), firstIssues.Round(time.Millisecond), issues, flows, lastChunk.Round(time.Millisecond))
	t.Logf("peak heap of the process: %d MB (including the test's own parsing)", peak.Load()>>20)

	assert.Equal(t, []string{chunkSummary, chunkOverview, chunkIssues, chunkFlows, chunkDone}, order, "the verdict first, then the lists")
	assert.Equal(t, counted, issues, "every issue arrives")
	assert.Equal(t, countedFlows, flows, "every flow arrives")
	assert.Greater(t, issues, 100, "the synthetic capture has issues to stream in batches")
	assert.Less(t, firstChunk, time.Second, "the verdict does not wait for the lists")
	assert.Less(t, firstChunk, lastChunk/2+time.Millisecond, "most of the stream comes after the verdict")
	budget := uint64(packets)*4000 + 150<<20
	assert.Less(t, peak.Load(), budget, fmt.Sprintf("peak heap should stay under ~4 KB per packet plus 150 MB, was %d MB", peak.Load()>>20))
}
