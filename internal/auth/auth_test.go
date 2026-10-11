package auth

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

var fixedNow = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

// open returns a fast service on a fresh credentials file.
func open(t *testing.T, opts ...Option) (*Service, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), CredentialsFileName)
	svc, err := Open(path, append([]Option{WithBcryptCost(bcrypt.MinCost)}, opts...)...)
	require.NoError(t, err)
	return svc, path
}

func readStored(t *testing.T, path string) stored {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var s stored
	require.NoError(t, json.Unmarshal(raw, &s))
	return s
}

func TestOpenCreatesTheDefaultAdmin(t *testing.T) {
	svc, path := open(t)

	assert.Equal(t, "admin", svc.Username())
	assert.True(t, svc.MustChangePassword())
	assert.Equal(t, path, svc.Path())

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "only the owner may read the hash and the secret")

	s := readStored(t, path)
	assert.Equal(t, "admin", s.Username)
	assert.NotContains(t, s.PasswordHash, "admin", "the password is never stored in clear")
	assert.True(t, strings.HasPrefix(s.PasswordHash, "$2"), "a bcrypt hash")
	require.NoError(t, bcrypt.CompareHashAndPassword([]byte(s.PasswordHash), []byte("admin")))
	secret, err := base64.StdEncoding.DecodeString(s.JWTSecret)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(secret), 32, "a random signing secret")
	assert.True(t, s.MustChangePassword)

	// no temporary files are left in the directory
	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	assert.Len(t, entries, 1)
}

func TestOpenReusesAnExistingFile(t *testing.T) {
	svc, path := open(t)
	_, _, err := svc.ChangePassword("admin", "second-password")
	require.NoError(t, err)
	before, err := os.ReadFile(path)
	require.NoError(t, err)

	again, err := Open(path, WithBcryptCost(bcrypt.MinCost))
	require.NoError(t, err)
	assert.False(t, again.MustChangePassword())
	assert.NoError(t, again.Verify("admin", "second-password"))
	assert.Error(t, again.Verify("admin", "admin"))
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, string(before), string(after), "opening does not rewrite the file")
}

func TestOpenRefusesDamagedFilesAndLeavesThemAlone(t *testing.T) {
	good, _ := open(t)
	goodHash := readStored(t, good.Path()).PasswordHash

	tests := []struct {
		name, content, wantErr string
	}{
		{"not json", "this is not json", "not valid JSON"},
		{"empty file", "", "not valid JSON"},
		{"no hash", `{"username":"admin","jwt_secret":"x"}`, "no username or password hash"},
		{"no username", `{"password_hash":"` + goodHash + `"}`, "no username or password hash"},
		{"hash that is not bcrypt", `{"username":"admin","password_hash":"plaintext","jwt_secret":"x"}`, "invalid password hash"},
		{"secret that is not base64", `{"username":"admin","password_hash":"` + goodHash + `","jwt_secret":"!!!"}`, "invalid jwt_secret"},
		{"secret that is too short", `{"username":"admin","password_hash":"` + goodHash + `","jwt_secret":"` + base64.StdEncoding.EncodeToString([]byte("short")) + `"}`, "invalid jwt_secret"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "c.json")
			require.NoError(t, os.WriteFile(path, []byte(tt.content), 0o600))
			svc, err := Open(path, WithBcryptCost(bcrypt.MinCost))
			require.Error(t, err)
			assert.Nil(t, svc)
			assert.Contains(t, err.Error(), tt.wantErr)
			raw, _ := os.ReadFile(path)
			assert.Equal(t, tt.content, string(raw), "a file we cannot read is never overwritten with the default login")
		})
	}
}

func TestOpenGeneratesAMissingSecret(t *testing.T) {
	svc, path := open(t)
	s := readStored(t, path)
	s.JWTSecret = ""
	raw, err := json.Marshal(s)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	_ = svc

	again, err := Open(path, WithBcryptCost(bcrypt.MinCost))
	require.NoError(t, err)
	assert.NotEmpty(t, readStored(t, path).JWTSecret, "an edited file gets a fresh secret and is saved")
	assert.NoError(t, again.Verify("admin", "admin"), "the password still works")
}

func TestOpenReportsUnwritableLocations(t *testing.T) {
	_, err := Open(filepath.Join(t.TempDir(), "no-such-dir", "c.json"), WithBcryptCost(bcrypt.MinCost))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "write credentials file")

	dir := t.TempDir()
	_, err = Open(dir, WithBcryptCost(bcrypt.MinCost)) // a directory where the file should be
	require.Error(t, err)
}

func TestDefaultPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	assert.Equal(t, filepath.Join(home, ".netforensic-credentials.json"), DefaultPath())
	t.Setenv("HOME", "")
	assert.Equal(t, CredentialsFileName, DefaultPath(), "the current directory when there is no home")
}

func TestVerify(t *testing.T) {
	svc, _ := open(t)
	assert.NoError(t, svc.Verify("admin", "admin"))
	assert.ErrorIs(t, svc.Verify("admin", "wrong"), ErrInvalidCredentials)
	assert.ErrorIs(t, svc.Verify("admin", ""), ErrInvalidCredentials)
	assert.ErrorIs(t, svc.Verify("admin", "ADMIN"), ErrInvalidCredentials)
	assert.ErrorIs(t, svc.Verify("root", "admin"), ErrInvalidCredentials, "the right password for the wrong user")
	assert.ErrorIs(t, svc.Verify("", ""), ErrInvalidCredentials)
	assert.ErrorIs(t, svc.Verify("Admin", "admin"), ErrInvalidCredentials, "user names are case-sensitive")
}

func TestLoginAndTokens(t *testing.T) {
	now := fixedNow
	svc, _ := open(t, WithClock(func() time.Time { return now }))

	token, expires, err := svc.Login("admin", "admin")
	require.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.Equal(t, fixedNow.Add(24*time.Hour), expires, "valid for 24 hours")

	user, err := svc.ValidateToken("Bearer " + token)
	require.NoError(t, err)
	assert.Equal(t, "admin", user)

	_, _, err = svc.Login("admin", "nope")
	assert.ErrorIs(t, err, ErrInvalidCredentials)
	_, _, err = svc.Login("nobody", "admin")
	assert.ErrorIs(t, err, ErrInvalidCredentials)

	// the token is a standard HS256 JWT with the usual claims
	parsed, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	require.NoError(t, err)
	assert.Equal(t, "HS256", parsed.Method.Alg())
	claims := parsed.Claims.(jwt.MapClaims)
	assert.Equal(t, "admin", claims["sub"])
	assert.Equal(t, "netforensic", claims["iss"])
	assert.EqualValues(t, fixedNow.Unix(), claims["iat"])
	assert.EqualValues(t, fixedNow.Add(24*time.Hour).Unix(), claims["exp"])
	assert.NotContains(t, token, "admin\"", "no password anywhere in it")

	t.Run("expiry", func(t *testing.T) {
		now = fixedNow.Add(24*time.Hour - time.Second)
		_, err := svc.ValidateToken("Bearer " + token)
		assert.NoError(t, err, "still valid a second before the end")
		now = fixedNow.Add(24*time.Hour + time.Second)
		_, err = svc.ValidateToken("Bearer " + token)
		assert.ErrorIs(t, err, ErrInvalidToken)
		now = fixedNow
	})
	t.Run("not yet valid", func(t *testing.T) {
		now = fixedNow.Add(-time.Hour)
		_, err := svc.ValidateToken("Bearer " + token)
		assert.ErrorIs(t, err, ErrInvalidToken, "a token from the future is refused")
		now = fixedNow
	})
}

func TestValidateTokenRejections(t *testing.T) {
	svc, _ := open(t, WithClock(func() time.Time { return fixedNow }))
	good, _, err := svc.Login("admin", "admin")
	require.NoError(t, err)

	sign := func(method jwt.SigningMethod, key any, claims jwt.Claims) string {
		s, err := jwt.NewWithClaims(method, claims).SignedString(key)
		require.NoError(t, err)
		return s
	}
	valid := func() jwt.RegisteredClaims {
		return jwt.RegisteredClaims{Issuer: "netforensic", Subject: "admin", IssuedAt: jwt.NewNumericDate(fixedNow), ExpiresAt: jwt.NewNumericDate(fixedNow.Add(time.Hour))}
	}
	secret, err := base64.StdEncoding.DecodeString(readStored(t, svc.Path()).JWTSecret)
	require.NoError(t, err)

	other, _ := open(t) // another installation: a different secret
	foreign, _, err := other.Login("admin", "admin")
	require.NoError(t, err)

	noExp := valid()
	noExp.ExpiresAt = nil
	wrongIss := valid()
	wrongIss.Issuer = "someone-else"
	wrongSub := valid()
	wrongSub.Subject = "root"
	expired := valid()
	expired.ExpiresAt = jwt.NewNumericDate(fixedNow.Add(-time.Minute))

	// a valid claim set signed with the right key is accepted, so the cases below fail for their one defect
	user, err := svc.ValidateToken("Bearer " + sign(jwt.SigningMethodHS256, secret, valid()))
	require.NoError(t, err)
	assert.Equal(t, "admin", user)

	tests := []struct {
		name   string
		header string
		want   error
	}{
		{"no header", "", ErrMissingToken},
		{"scheme only", "Bearer", ErrMissingToken},
		{"scheme and spaces", "Bearer   ", ErrMissingToken},
		{"other scheme", "Basic YWRtaW46YWRtaW4=", ErrMissingToken},
		{"token without scheme", good, ErrMissingToken},
		{"garbage", "Bearer not-a-jwt", ErrInvalidToken},
		{"two parts", "Bearer abc.def", ErrInvalidToken},
		{"signed by another installation", "Bearer " + foreign, ErrInvalidToken},
		{"tampered payload", "Bearer " + strings.Join([]string{strings.Split(good, ".")[0], base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"admin","iss":"netforensic","exp":9999999999}`)), strings.Split(good, ".")[2]}, "."), ErrInvalidToken},
		{"alg none", "Bearer " + sign(jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, valid()), ErrInvalidToken},
		{"HS512 instead of HS256", "Bearer " + sign(jwt.SigningMethodHS512, secret, valid()), ErrInvalidToken},
		{"no expiry", "Bearer " + sign(jwt.SigningMethodHS256, secret, noExp), ErrInvalidToken},
		{"expired", "Bearer " + sign(jwt.SigningMethodHS256, secret, expired), ErrInvalidToken},
		{"wrong issuer", "Bearer " + sign(jwt.SigningMethodHS256, secret, wrongIss), ErrInvalidToken},
		{"another user", "Bearer " + sign(jwt.SigningMethodHS256, secret, wrongSub), ErrInvalidToken},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := svc.ValidateToken(tt.header)
			assert.ErrorIs(t, err, tt.want)
			assert.Empty(t, user)
		})
	}

	t.Run("the scheme is case-insensitive and tolerates spaces", func(t *testing.T) {
		for _, h := range []string{"bearer " + good, "BEARER " + good, "  Bearer " + good + "  "} {
			_, err := svc.ValidateToken(h)
			assert.NoError(t, err, h)
		}
	})
}

func TestChangePassword(t *testing.T) {
	svc, path := open(t, WithClock(func() time.Time { return fixedNow }))
	oldToken, _, err := svc.Login("admin", "admin")
	require.NoError(t, err)
	oldSecret := readStored(t, path).JWTSecret

	t.Run("wrong old password", func(t *testing.T) {
		_, _, err := svc.ChangePassword("not-admin", "new-password")
		assert.ErrorIs(t, err, ErrInvalidCredentials)
		assert.NoError(t, svc.Verify("admin", "admin"), "nothing changed")
		assert.True(t, svc.MustChangePassword())
	})
	t.Run("too short", func(t *testing.T) {
		_, _, err := svc.ChangePassword("admin", "12345")
		assert.ErrorIs(t, err, ErrPasswordTooShort)
		_, _, err = svc.ChangePassword("admin", "")
		assert.ErrorIs(t, err, ErrPasswordTooShort)
		assert.NoError(t, svc.Verify("admin", "admin"))
	})
	t.Run("the minimum length is accepted by the length rule", func(t *testing.T) {
		assert.Equal(t, 6, MinPasswordLength)
	})
	t.Run("too long for bcrypt", func(t *testing.T) {
		_, _, err := svc.ChangePassword("admin", strings.Repeat("x", 73))
		assert.ErrorIs(t, err, ErrPasswordTooLong)
		assert.NoError(t, svc.Verify("admin", "admin"))
	})
	t.Run("the default password is itself too short to be reused", func(t *testing.T) {
		_, _, err := svc.ChangePassword("admin", "admin")
		assert.ErrorIs(t, err, ErrPasswordTooShort, "so the default login can never be set again")
	})
	t.Run("the old password is checked before the new one", func(t *testing.T) {
		_, _, err := svc.ChangePassword("wrong", "x")
		assert.ErrorIs(t, err, ErrInvalidCredentials, "a stranger learns nothing about the password rules")
	})

	// the successful change
	newToken, expires, err := svc.ChangePassword("admin", strings.Repeat("y", 72))
	require.NoError(t, err)
	assert.Equal(t, fixedNow.Add(24*time.Hour), expires)
	assert.False(t, svc.MustChangePassword())
	assert.NoError(t, svc.Verify("admin", strings.Repeat("y", 72)), "the longest accepted password")
	assert.ErrorIs(t, svc.Verify("admin", "admin"), ErrInvalidCredentials, "the old password stops working")

	_, err = svc.ValidateToken("Bearer " + oldToken)
	assert.ErrorIs(t, err, ErrInvalidToken, "sessions started with the old password end")
	_, err = svc.ValidateToken("Bearer " + newToken)
	assert.NoError(t, err, "the session that changed it continues")

	_, _, err = svc.ChangePassword(strings.Repeat("y", 72), strings.Repeat("y", 72))
	assert.ErrorIs(t, err, ErrPasswordUnchanged, "setting the same password again is refused")

	s := readStored(t, path)
	assert.NotEqual(t, oldSecret, s.JWTSecret, "the signing secret was replaced")
	assert.False(t, s.MustChangePassword)
	assert.NoError(t, bcrypt.CompareHashAndPassword([]byte(s.PasswordHash), []byte(strings.Repeat("y", 72))))
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	// and it survives a restart
	again, err := Open(path, WithBcryptCost(bcrypt.MinCost), WithClock(func() time.Time { return fixedNow }))
	require.NoError(t, err)
	assert.NoError(t, again.Verify("admin", strings.Repeat("y", 72)))
	_, err = again.ValidateToken("Bearer " + newToken)
	assert.NoError(t, err, "tokens survive a restart: the secret is in the file")
}

func TestChangePasswordKeepsTheOldOneIfItCannotBeSaved(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("directory permissions do not bind root")
	}
	svc, path := open(t)
	dir := filepath.Dir(path)
	token, _, err := svc.Login("admin", "admin")
	require.NoError(t, err)
	require.NoError(t, os.Chmod(dir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	_, _, err = svc.ChangePassword("admin", "new-password")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "write credentials file")

	assert.NoError(t, svc.Verify("admin", "admin"), "the old password still works")
	assert.ErrorIs(t, svc.Verify("admin", "new-password"), ErrInvalidCredentials)
	assert.True(t, svc.MustChangePassword())
	_, err = svc.ValidateToken("Bearer " + token)
	assert.NoError(t, err, "and so do the existing sessions")
}

func TestConcurrentUse(t *testing.T) {
	svc, _ := open(t)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, _, err := svc.Login("admin", "admin")
			if err == nil {
				_, _ = svc.ValidateToken("Bearer " + token)
			}
			_ = svc.MustChangePassword()
		}()
	}
	wg.Wait()
}
