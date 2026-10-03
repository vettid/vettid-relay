// Package fakes3 is a minimal in-memory S3 endpoint for tests: path-style
// PutObject, GetObject and DeleteObject on any bucket — exactly what the
// relay's blob storage uses. It keeps tests off the network and off another
// container.
package fakes3

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Server is a fake S3 endpoint.
type Server struct {
	mu      sync.Mutex
	objects map[string][]byte // "bucket/key"
	ts      *httptest.Server
}

// New starts a fake S3 server, closed when the test ends.
func New(t testing.TB) *Server {
	s := &Server{objects: map[string][]byte{}}
	s.ts = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.ts.Close)
	return s
}

// URL is the endpoint to configure the S3 client with (path-style).
func (s *Server) URL() string { return s.ts.URL }

// Client returns an S3 client for this server.
func (s *Server) Client() *s3.Client {
	return s3.New(s3.Options{
		Region:                     "us-east-1",
		BaseEndpoint:               aws.String(s.ts.URL),
		UsePathStyle:               true,
		Credentials:                aws.AnonymousCredentials{},
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired,
	})
}

// Len returns the number of stored objects.
func (s *Server) Len() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.objects) }

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	if !strings.Contains(path, "/") {
		http.Error(w, "bucket operations are not supported", http.StatusNotImplemented)
		return
	}
	switch r.Method {
	case http.MethodPut:
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		s.objects[path] = b
		s.mu.Unlock()
		w.Header().Set("ETag", `"fake"`)
		w.WriteHeader(http.StatusOK)
	case http.MethodGet, http.MethodHead:
		s.mu.Lock()
		b, ok := s.objects[path]
		s.mu.Unlock()
		if !ok {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusNotFound)
			if r.Method == http.MethodGet {
				io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>`)
			}
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(b)))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			w.Write(b)
		}
	case http.MethodDelete:
		s.mu.Lock()
		delete(s.objects, path)
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "unsupported", http.StatusNotImplemented)
	}
}
