package relay

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/mrgyatso/keyhole/internal/proto"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError answers with a proto.HTTPError body.
func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, proto.HTTPError{Error: proto.Error{Code: code, Message: msg}})
}

// decodeBody decodes a JSON body of at most limit bytes into v. If it
// cannot, it answers the request itself and returns false.
func decodeBody(w http.ResponseWriter, r *http.Request, limit int64, v any) bool {
	return decode(w, r, limit, v, false)
}

// decodeOptionalBody is decodeBody for requests whose body may be empty.
func decodeOptionalBody(w http.ResponseWriter, r *http.Request, limit int64, v any) bool {
	return decode(w, r, limit, v, true)
}

func decode(w http.ResponseWriter, r *http.Request, limit int64, v any, optional bool) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	err := dec.Decode(v)
	if err == nil {
		var extra json.RawMessage
		if err = dec.Decode(&extra); err == io.EOF {
			return true
		} else if err == nil {
			err = errors.New("unexpected data after the JSON value")
		}
	} else if optional && err == io.EOF {
		return true
	}
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		writeError(w, http.StatusRequestEntityTooLarge, proto.ErrBadRequest,
			fmt.Sprintf("request body is larger than %d bytes", limit))
		return false
	}
	writeError(w, http.StatusBadRequest, proto.ErrBadRequest, "malformed JSON body: "+err.Error())
	return false
}

// logRequests logs one line per request: method, path, status, duration and
// client IP. Secrets travel only in headers and bodies, which are never
// logged.
func (s *Server) logRequests(listener string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		defer func() {
			s.log.Info("http request", "listener", listener, "method", r.Method, "path", r.URL.Path,
				"status", sw.statusCode(), "ms", time.Since(start).Milliseconds(), "ip", clientIP(r))
		}()
		next.ServeHTTP(sw, r)
	})
}

// statusWriter records the response status. It passes Flush through, which
// streaming MCP responses need.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *statusWriter) statusCode() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}
