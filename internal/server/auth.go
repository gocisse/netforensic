package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/gocisse/netforensic/internal/auth"
)

// maxJSONBody bounds the body of the small JSON requests of the auth API.
const maxJSONBody = 16 << 10

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type changePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

// tokenResponse is the answer to a successful login or password change.
type tokenResponse struct {
	Token string `json:"token"`
	// ExpiresAt is when the token stops working.
	ExpiresAt time.Time `json:"expires_at"`
	Username  string    `json:"username"`
	// MustChangePassword is true while the default password is in use, so a
	// UI can send the user to the password form first.
	MustChangePassword bool `json:"must_change_password"`
}

type messageResponse struct {
	Message string `json:"message"`
}

// decodeJSON reads a small JSON request body into v. It writes the error
// response itself and reports false if the body is unusable.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var tooBig *http.MaxBytesError
		switch {
		case errors.As(err, &tooBig):
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		default:
			writeError(w, http.StatusBadRequest, "expected a JSON body with the documented fields")
		}
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) { // trailing data after the object
		writeError(w, http.StatusBadRequest, "expected a single JSON object")
		return false
	}
	return true
}

// requirePost answers anything but POST with 405 and reports whether it did.
func requirePost(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodPost {
		return true
	}
	w.Header().Set("Allow", http.MethodPost)
	writeError(w, http.StatusMethodNotAllowed, "use POST")
	return false
}

// noStore keeps credentials and tokens out of caches.
func noStore(w http.ResponseWriter) { w.Header().Set("Cache-Control", "no-store") }

// requireAuth lets a request through only if it carries a valid bearer token.
func (h *handler) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := h.auth.ValidateToken(r.Header.Get("Authorization")); err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="netforensic"`)
			noStore(w)
			writeError(w, http.StatusUnauthorized, err.Error())
			return
		}
		next(w, r)
	}
}

// login handles POST /api/login.
func (h *handler) login(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	noStore(w)
	var req loginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	token, expires, err := h.auth.Login(req.Username, req.Password)
	if err != nil {
		writeError(w, http.StatusUnauthorized, auth.ErrInvalidCredentials.Error())
		return
	}
	writeJSON(w, http.StatusOK, tokenResponse{
		Token: token, ExpiresAt: expires, Username: req.Username, MustChangePassword: h.auth.MustChangePassword(),
	})
}

// changePassword handles POST /api/change-password. It is behind requireAuth.
func (h *handler) changePassword(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	noStore(w)
	var req changePasswordRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	token, expires, err := h.auth.ChangePassword(req.OldPassword, req.NewPassword)
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		writeError(w, http.StatusUnauthorized, "old password is incorrect")
	case errors.Is(err, auth.ErrPasswordTooShort), errors.Is(err, auth.ErrPasswordTooLong), errors.Is(err, auth.ErrPasswordUnchanged):
		writeError(w, http.StatusBadRequest, err.Error())
	case err != nil:
		writeError(w, http.StatusInternalServerError, "could not store the new password")
	default:
		// Every earlier token stopped working with the old password, so the
		// answer carries a fresh one for this session.
		writeJSON(w, http.StatusOK, tokenResponse{Token: token, ExpiresAt: expires, Username: h.auth.Username()})
	}
}

// logout handles POST /api/logout. Tokens are stateless, so signing out is
// the client discarding its token; there is nothing to revoke on the server.
func (h *handler) logout(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	noStore(w)
	writeJSON(w, http.StatusOK, messageResponse{Message: "signed out; discard the token"})
}
