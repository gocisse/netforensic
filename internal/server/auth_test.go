package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/gocisse/netforensic/internal/auth"
	"github.com/gocisse/netforensic/internal/models"
)

// authEnv is a handler without the test shortcut of authed: every request
// has to bring its own token.
type authEnv struct {
	svc *auth.Service
	h   http.Handler
	now time.Time
}

func newAuthEnv(t *testing.T) *authEnv {
	t.Helper()
	env := &authEnv{now: time.Now()}
	svc, err := auth.Open(t.TempDir()+"/"+auth.CredentialsFileName, auth.WithBcryptCost(bcrypt.MinCost), auth.WithClock(func() time.Time { return env.now }))
	require.NoError(t, err)
	env.svc = svc
	env.h = newHandler(testAssets, maxUploadBytes, svc)
	return env
}

func (e *authEnv) do(t *testing.T, method, path, contentType, token string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

func (e *authEnv) postJSON(t *testing.T, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	return e.do(t, http.MethodPost, path, "application/json", token, []byte(body))
}

func (e *authEnv) login(t *testing.T, user, pass string) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"username": user, "password": pass})
	return e.postJSON(t, "/api/login", "", string(b))
}

func (e *authEnv) token(t *testing.T) string {
	t.Helper()
	rec := e.login(t, "admin", "admin")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var tr tokenResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &tr))
	return tr.Token
}

func (e *authEnv) analyze(t *testing.T, token string) *httptest.ResponseRecorder {
	t.Helper()
	body, ct := upload(t, "file", "Lab-7-TCPIssues.pcapng", readFile(t, lab7))
	return e.do(t, http.MethodPost, "/api/analyze", ct, token, body.Bytes())
}

func TestLoginSucceedsWithTheDefaultAdmin(t *testing.T) {
	env := newAuthEnv(t)
	rec := env.login(t, "admin", "admin")

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	var tr tokenResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &tr))
	assert.NotEmpty(t, tr.Token)
	assert.Equal(t, "admin", tr.Username)
	assert.True(t, tr.MustChangePassword, "the default password has to be changed")
	assert.WithinDuration(t, env.now.Add(24*time.Hour), tr.ExpiresAt, time.Second)

	user, err := env.svc.ValidateToken("Bearer " + tr.Token)
	require.NoError(t, err)
	assert.Equal(t, "admin", user)
	assert.Equal(t, 3, strings.Count(tr.Token, ".")+1, "a JWT has three parts")
	assert.NotContains(t, rec.Body.String(), "password_hash")
}

func TestLoginFailures(t *testing.T) {
	env := newAuthEnv(t)

	t.Run("wrong password", func(t *testing.T) {
		rec := env.login(t, "admin", "wrong")
		assertJSONError(t, rec, http.StatusUnauthorized, "invalid username or password")
		assert.NotContains(t, rec.Body.String(), "token")
	})
	t.Run("wrong user and wrong password say the same", func(t *testing.T) {
		a := env.login(t, "admin", "wrong")
		b := env.login(t, "nobody", "wrong")
		c := env.login(t, "nobody", "admin")
		assert.Equal(t, a.Body.String(), b.Body.String(), "no hint about which part was wrong")
		assert.Equal(t, a.Body.String(), c.Body.String())
		assert.Equal(t, http.StatusUnauthorized, c.Code)
	})
	t.Run("empty credentials", func(t *testing.T) {
		assertJSONError(t, env.login(t, "", ""), http.StatusUnauthorized, "invalid username or password")
	})
	t.Run("malformed bodies", func(t *testing.T) {
		for _, body := range []string{"", "not json", `{"username":"admin"`, `[]`, `{"username":"admin","password":"admin","extra":1}`, `{"username":"admin","password":"admin"} {"x":1}`, `{"username":1}`} {
			assertJSONError(t, env.postJSON(t, "/api/login", "", body), http.StatusBadRequest, "JSON")
		}
	})
	t.Run("an oversized body", func(t *testing.T) {
		big := `{"username":"admin","password":"` + strings.Repeat("a", 20<<10) + `"}`
		assertJSONError(t, env.postJSON(t, "/api/login", "", big), http.StatusRequestEntityTooLarge, "too large")
	})
	t.Run("only POST", func(t *testing.T) {
		rec := env.do(t, http.MethodGet, "/api/login", "", "", nil)
		assertJSONError(t, rec, http.StatusMethodNotAllowed, "use POST")
		assert.Equal(t, http.MethodPost, rec.Header().Get("Allow"))
	})
}

func TestAnalyzeNeedsAToken(t *testing.T) {
	env := newAuthEnv(t)

	t.Run("without a token", func(t *testing.T) {
		rec := env.analyze(t, "")
		assertJSONError(t, rec, http.StatusUnauthorized, "missing bearer token")
		assert.Equal(t, `Bearer realm="netforensic"`, rec.Header().Get("WWW-Authenticate"))
		assert.NotContains(t, rec.Body.String(), "total_packets", "nothing is analyzed")
	})
	t.Run("with garbage", func(t *testing.T) {
		assertJSONError(t, env.analyze(t, "not.a.token"), http.StatusUnauthorized, "invalid or expired token")
	})
	t.Run("with a token signed by someone else", func(t *testing.T) {
		forged, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
			Issuer: "netforensic", Subject: "admin", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		}).SignedString([]byte("guessed-secret"))
		require.NoError(t, err)
		assertJSONError(t, env.analyze(t, forged), http.StatusUnauthorized, "invalid or expired token")
	})
	t.Run("with an unsigned token", func(t *testing.T) {
		unsigned, err := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.RegisteredClaims{
			Issuer: "netforensic", Subject: "admin", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		}).SignedString(jwt.UnsafeAllowNoneSignatureType)
		require.NoError(t, err)
		assertJSONError(t, env.analyze(t, unsigned), http.StatusUnauthorized, "invalid or expired token")
	})
	t.Run("with another scheme", func(t *testing.T) {
		body, ct := upload(t, "file", "a.pcapng", readFile(t, lab7))
		req := httptest.NewRequest(http.MethodPost, "/api/analyze", body)
		req.Header.Set("Content-Type", ct)
		req.Header.Set("Authorization", "Basic YWRtaW46YWRtaW4=")
		rec := httptest.NewRecorder()
		env.h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})
	t.Run("with an expired token", func(t *testing.T) {
		token := env.token(t)
		env.now = env.now.Add(25 * time.Hour)
		defer func() { env.now = env.now.Add(-25 * time.Hour) }()
		assertJSONError(t, env.analyze(t, token), http.StatusUnauthorized, "invalid or expired token")
	})
	t.Run("a GET without a token is refused too", func(t *testing.T) {
		assert.Equal(t, http.StatusUnauthorized, env.do(t, http.MethodGet, "/api/analyze", "", "", nil).Code)
	})
}

func TestAnalyzeWithAValidToken(t *testing.T) {
	env := newAuthEnv(t)
	rec := env.analyze(t, env.token(t))

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var res models.AnalysisResult
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &res))
	assert.Equal(t, "Lab-7-TCPIssues.pcapng", res.FileName)
	assert.Equal(t, 64, res.TotalPackets)
	assert.Equal(t, 80, res.Diagnosis.HealthScore)
	assert.Equal(t, "Connection reset after zero-window stall", res.Diagnosis.PrimaryCause)
}

func TestTheUIAndLoginStayPublic(t *testing.T) {
	env := newAuthEnv(t)
	rec := env.do(t, http.MethodGet, "/", "", "", nil)
	assert.Equal(t, http.StatusOK, rec.Code, "the page that shows the login form must load without a token")
	assert.Equal(t, http.StatusOK, env.do(t, http.MethodGet, "/assets/app.js", "", "", nil).Code)
}

func TestChangePasswordSucceedsWithTheOldPassword(t *testing.T) {
	env := newAuthEnv(t)
	token := env.token(t)

	rec := env.postJSON(t, "/api/change-password", token, `{"old_password":"admin","new_password":"a-new-secret"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	var tr tokenResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &tr))
	assert.NotEmpty(t, tr.Token)
	assert.False(t, tr.MustChangePassword)
	assert.NotEqual(t, token, tr.Token)

	t.Run("the new password logs in, the old one does not", func(t *testing.T) {
		assert.Equal(t, http.StatusOK, env.login(t, "admin", "a-new-secret").Code)
		assertJSONError(t, env.login(t, "admin", "admin"), http.StatusUnauthorized, "invalid username or password")
		var again tokenResponse
		require.NoError(t, json.Unmarshal(env.login(t, "admin", "a-new-secret").Body.Bytes(), &again))
		assert.False(t, again.MustChangePassword, "the warning is gone")
	})
	t.Run("the old token stopped working, the fresh one works", func(t *testing.T) {
		assertJSONError(t, env.analyze(t, token), http.StatusUnauthorized, "invalid or expired token")
		assert.Equal(t, http.StatusOK, env.analyze(t, tr.Token).Code)
	})
	t.Run("it is stored for the next start", func(t *testing.T) {
		again, err := auth.Open(env.svc.Path(), auth.WithBcryptCost(bcrypt.MinCost))
		require.NoError(t, err)
		assert.NoError(t, again.Verify("admin", "a-new-secret"))
		raw, err := os.ReadFile(env.svc.Path())
		require.NoError(t, err)
		assert.NotContains(t, string(raw), "a-new-secret", "only the hash is on disk")
	})
}

func TestChangePasswordRejections(t *testing.T) {
	env := newAuthEnv(t)
	token := env.token(t)

	t.Run("wrong old password", func(t *testing.T) {
		rec := env.postJSON(t, "/api/change-password", token, `{"old_password":"nope","new_password":"a-new-secret"}`)
		assertJSONError(t, rec, http.StatusUnauthorized, "old password is incorrect")
		assert.Equal(t, http.StatusOK, env.login(t, "admin", "admin").Code, "nothing changed")
		assert.Equal(t, http.StatusOK, env.analyze(t, token).Code, "and the session goes on")
	})
	t.Run("new password too short", func(t *testing.T) {
		rec := env.postJSON(t, "/api/change-password", token, `{"old_password":"admin","new_password":"12345"}`)
		assertJSONError(t, rec, http.StatusBadRequest, "at least 6 characters")
		assert.Equal(t, http.StatusOK, env.login(t, "admin", "admin").Code)
	})
	t.Run("six characters are enough", func(t *testing.T) {
		probe := newAuthEnv(t)
		rec := probe.postJSON(t, "/api/change-password", probe.token(t), `{"old_password":"admin","new_password":"123456"}`)
		assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	})
	t.Run("new password too long", func(t *testing.T) {
		rec := env.postJSON(t, "/api/change-password", token, `{"old_password":"admin","new_password":"`+strings.Repeat("x", 73)+`"}`)
		assertJSONError(t, rec, http.StatusBadRequest, "at most 72 bytes")
	})
	t.Run("a wrong old password is reported before a short new one", func(t *testing.T) {
		rec := env.postJSON(t, "/api/change-password", token, `{"old_password":"nope","new_password":"1"}`)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})
	t.Run("no token", func(t *testing.T) {
		rec := env.postJSON(t, "/api/change-password", "", `{"old_password":"admin","new_password":"a-new-secret"}`)
		assertJSONError(t, rec, http.StatusUnauthorized, "missing bearer token")
		assert.Equal(t, http.StatusOK, env.login(t, "admin", "admin").Code, "the password was not changed")
	})
	t.Run("a bad token", func(t *testing.T) {
		rec := env.postJSON(t, "/api/change-password", "x.y.z", `{"old_password":"admin","new_password":"a-new-secret"}`)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})
	t.Run("malformed body and wrong method", func(t *testing.T) {
		assertJSONError(t, env.postJSON(t, "/api/change-password", token, `{"old_password":"admin"`), http.StatusBadRequest, "JSON")
		assertJSONError(t, env.postJSON(t, "/api/change-password", token, `{"old":"x"}`), http.StatusBadRequest, "JSON")
		rec := env.do(t, http.MethodGet, "/api/change-password", "", token, nil)
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	})
}

func TestLogout(t *testing.T) {
	env := newAuthEnv(t)
	rec := env.postJSON(t, "/api/logout", "", ``)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "discard the token")
	assert.Equal(t, http.MethodPost, env.do(t, http.MethodGet, "/api/logout", "", "", nil).Header().Get("Allow"))

	// tokens are stateless: a logout does not revoke anything
	token := env.token(t)
	env.postJSON(t, "/api/logout", token, ``)
	assert.Equal(t, http.StatusOK, env.analyze(t, token).Code)
}

func TestTokenCarriesNoPassword(t *testing.T) {
	// the token carries who and until when, never the password
	env := newAuthEnv(t)
	token := env.token(t)
	parts := strings.Split(token, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	assert.NotContains(t, string(payload), "password")
	assert.Contains(t, string(payload), `"sub":"admin"`)
}
