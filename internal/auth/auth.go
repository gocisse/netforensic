// Package auth provides the login, token and password handling of the web UI.
//
// There is a single user. Its bcrypt-hashed password lives in a small JSON
// file together with the secret that signs the JWT tokens. On first use the
// file is created with the default login admin/admin, and the service reports
// that the password must be changed.
package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	// DefaultUsername and DefaultPassword are the login of a fresh installation.
	DefaultUsername = "admin"
	DefaultPassword = "admin"

	// CredentialsFileName is the file name of the credentials file.
	CredentialsFileName = ".netforensic-credentials.json"

	// TokenLifetime is how long a token stays valid.
	TokenLifetime = 24 * time.Hour

	// MinPasswordLength and MaxPasswordLength bound new passwords. bcrypt
	// only looks at the first 72 bytes, so longer passwords are refused
	// instead of being silently cut.
	MinPasswordLength = 6
	MaxPasswordLength = 72

	issuer     = "netforensic"
	secretSize = 32
)

// Errors returned by the service.
var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrMissingToken       = errors.New("missing bearer token")
	ErrInvalidToken       = errors.New("invalid or expired token")
	ErrPasswordTooShort   = fmt.Errorf("new password must be at least %d characters", MinPasswordLength)
	ErrPasswordTooLong    = fmt.Errorf("new password must be at most %d bytes", MaxPasswordLength)
	ErrPasswordUnchanged  = errors.New("new password must differ from the old one")
)

// User is the account that may use the web UI.
type User struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"` // bcrypt
}

// stored is the content of the credentials file.
type stored struct {
	User
	// JWTSecret signs the tokens. It is replaced whenever the password
	// changes, which ends every session started with the old password.
	JWTSecret          string `json:"jwt_secret"`
	MustChangePassword bool   `json:"must_change_password"`
}

// Service verifies logins, issues and checks tokens, and changes the password.
// It is safe for concurrent use.
type Service struct {
	path string
	cost int
	now  func() time.Time

	mu     sync.Mutex
	data   stored
	secret []byte
}

// Option configures a Service.
type Option func(*Service)

// WithBcryptCost sets the bcrypt cost, for tests that must be fast.
func WithBcryptCost(cost int) Option { return func(s *Service) { s.cost = cost } }

// WithClock replaces the clock, for tests of token expiry.
func WithClock(now func() time.Time) Option { return func(s *Service) { s.now = now } }

// DefaultPath returns where the credentials file lives: in the user's home
// directory, or in the current directory if there is none.
func DefaultPath() string {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, CredentialsFileName)
	}
	return CredentialsFileName
}

// Open loads the credentials file at path, creating it with the default
// admin/admin login if it does not exist. A file that exists but cannot be
// understood is an error; it is never overwritten.
func Open(path string, opts ...Option) (*Service, error) {
	s := &Service{path: path, cost: bcrypt.DefaultCost, now: time.Now}
	for _, o := range opts {
		o(s)
	}

	raw, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := s.createDefault(); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, fmt.Errorf("read credentials file: %w", err)
	default:
		if err := json.Unmarshal(raw, &s.data); err != nil {
			return nil, fmt.Errorf("credentials file %s is not valid JSON (fix or delete it): %w", path, err)
		}
		if s.data.Username == "" || s.data.PasswordHash == "" {
			return nil, fmt.Errorf("credentials file %s has no username or password hash (fix or delete it)", path)
		}
		if _, err := bcrypt.Cost([]byte(s.data.PasswordHash)); err != nil {
			return nil, fmt.Errorf("credentials file %s holds an invalid password hash (fix or delete it): %w", path, err)
		}
		if s.data.JWTSecret == "" { // an edited file: make the tokens safe again
			if err := s.rotateSecretLocked(); err != nil {
				return nil, err
			}
			if err := s.saveLocked(); err != nil {
				return nil, err
			}
		}
	}
	secret, err := base64.StdEncoding.DecodeString(s.data.JWTSecret)
	if err != nil || len(secret) < secretSize {
		return nil, fmt.Errorf("credentials file %s holds an invalid jwt_secret (fix or delete it)", path)
	}
	s.secret = secret
	return s, nil
}

func (s *Service) createDefault() error {
	hash, err := bcrypt.GenerateFromPassword([]byte(DefaultPassword), s.cost)
	if err != nil {
		return fmt.Errorf("hash default password: %w", err)
	}
	s.data = stored{User: User{Username: DefaultUsername, PasswordHash: string(hash)}, MustChangePassword: true}
	if err := s.rotateSecretLocked(); err != nil {
		return err
	}
	return s.saveLocked()
}

// rotateSecretLocked replaces the signing secret. The caller holds s.mu, or
// the service is not shared yet.
func (s *Service) rotateSecretLocked() error {
	secret := make([]byte, secretSize)
	if _, err := rand.Read(secret); err != nil {
		return fmt.Errorf("generate signing secret: %w", err)
	}
	s.secret = secret
	s.data.JWTSecret = base64.StdEncoding.EncodeToString(secret)
	return nil
}

// saveLocked writes the credentials file atomically with mode 0600.
func (s *Service) saveLocked() error {
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return fmt.Errorf("encode credentials: %w", err)
	}
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".netforensic-credentials-*.tmp") // created with mode 0600
	if err != nil {
		return fmt.Errorf("write credentials file: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		tmp.Close()
		return fmt.Errorf("write credentials file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write credentials file: %w", err)
	}
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		return fmt.Errorf("write credentials file: %w", err)
	}
	return nil
}

// Path returns the credentials file.
func (s *Service) Path() string { return s.path }

// Username returns the name of the account.
func (s *Service) Username() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.Username
}

// MustChangePassword reports whether the password is still the default one.
func (s *Service) MustChangePassword() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.MustChangePassword
}

// dummyHash is compared against when the username is wrong, so that a wrong
// username takes as long to reject as a wrong password.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("netforensic-dummy"), bcrypt.MinCost)

// Verify checks a username and password against the stored hash.
func (s *Service) Verify(username, password string) error {
	s.mu.Lock()
	user, hash := s.data.Username, s.data.PasswordHash
	s.mu.Unlock()

	userOK := username == user
	if !userOK {
		hash = string(dummyHash)
	}
	passOK := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
	if !userOK || !passOK {
		return ErrInvalidCredentials
	}
	return nil
}

// Login verifies the credentials and returns a signed token and the moment
// it expires.
func (s *Service) Login(username, password string) (token string, expires time.Time, err error) {
	if err := s.Verify(username, password); err != nil {
		return "", time.Time{}, err
	}
	return s.GenerateToken(username)
}

// GenerateToken returns an HS256-signed JWT for username that is valid for
// TokenLifetime, and its expiry.
func (s *Service) GenerateToken(username string) (string, time.Time, error) {
	s.mu.Lock()
	secret := s.secret
	s.mu.Unlock()

	now := s.now()
	expires := now.Add(TokenLifetime)
	claims := jwt.RegisteredClaims{
		Issuer:    issuer,
		Subject:   username,
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(expires),
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign token: %w", err)
	}
	return signed, expires, nil
}

// ValidateToken checks the token in an Authorization header ("Bearer ...")
// and returns the username it was issued to. A missing header gives
// ErrMissingToken; anything wrong with the token (bad signature, wrong
// algorithm, expired, issued for another user) gives ErrInvalidToken.
func (s *Service) ValidateToken(authorization string) (string, error) {
	scheme, token, ok := strings.Cut(strings.TrimSpace(authorization), " ")
	if authorization == "" || (ok && !strings.EqualFold(scheme, "Bearer")) {
		return "", ErrMissingToken
	}
	token = strings.TrimSpace(token)
	if !ok || token == "" {
		return "", ErrMissingToken
	}

	s.mu.Lock()
	secret, user := s.secret, s.data.Username
	s.mu.Unlock()

	claims := &jwt.RegisteredClaims{}
	parsed, err := jwt.ParseWithClaims(token, claims, func(*jwt.Token) (any, error) { return secret, nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(issuer),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(s.now),
	)
	if err != nil || !parsed.Valid || claims.Subject != user {
		return "", ErrInvalidToken
	}
	return claims.Subject, nil
}

// ChangePassword replaces the password after checking the old one. The
// signing secret is rotated, so every token issued before the change stops
// working; the caller gets a fresh token for the session that made the change.
func (s *Service) ChangePassword(oldPassword, newPassword string) (token string, expires time.Time, err error) {
	if err := s.Verify(s.Username(), oldPassword); err != nil {
		return "", time.Time{}, err
	}
	switch {
	case len(newPassword) < MinPasswordLength:
		return "", time.Time{}, ErrPasswordTooShort
	case len(newPassword) > MaxPasswordLength:
		return "", time.Time{}, ErrPasswordTooLong
	case newPassword == oldPassword:
		return "", time.Time{}, ErrPasswordUnchanged
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), s.cost)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("hash password: %w", err)
	}

	s.mu.Lock()
	previous, previousSecret := s.data, s.secret
	s.data.PasswordHash = string(hash)
	s.data.MustChangePassword = false
	if err := s.rotateSecretLocked(); err != nil {
		s.data, s.secret = previous, previousSecret
		s.mu.Unlock()
		return "", time.Time{}, err
	}
	if err := s.saveLocked(); err != nil { // keep the old password if it cannot be stored
		s.data, s.secret = previous, previousSecret
		s.mu.Unlock()
		return "", time.Time{}, err
	}
	username := s.data.Username
	s.mu.Unlock()

	return s.GenerateToken(username)
}
