package api

import (
	"bufio"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// recorder captures status, error code and bytes for the access log. It
// supports hijacking (WebSocket upgrade) and flushing.
type recorder struct {
	http.ResponseWriter
	status   int
	bytes    int64
	code     string
	hijacked bool
	attrs    []any    // extra non-sensitive log fields (msg ids, sizes, counts)
	rl       reqState // what the rate-limit middleware learned (limits.go)
}

func (r *recorder) WriteHeader(status int) {
	if r.status == 0 {
		r.status = status
	}
	r.ResponseWriter.WriteHeader(status)
}

func (r *recorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}

func (r *recorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (r *recorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("hijack not supported")
	}
	r.hijacked = true
	if r.status == 0 {
		r.status = http.StatusSwitchingProtocols
	}
	return h.Hijack()
}

func (r *recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// withAccessLog logs one structured line per request: route pattern (never
// the raw path, which contains mailbox/msg ids), status, error code, sizes and
// duration. It also recovers panics as `internal`.
func (s *Server) withAccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &recorder{ResponseWriter: w}
		defer func() {
			if p := recover(); p != nil {
				if p == http.ErrAbortHandler {
					panic(p)
				}
				s.log.Error("panic in handler", "route", r.Pattern, "panic", p)
				if rec.status == 0 && !rec.hijacked {
					s.writeError(rec, fail(CodeInternal))
				}
			}
			status := rec.status
			if status == 0 {
				status = http.StatusOK
			}
			route := r.Pattern
			if route == "" {
				route = "unmatched"
			}
			attrs := []slog.Attr{
				slog.String("route", route),
				slog.Int("status", status),
				slog.Int64("req_bytes", r.ContentLength),
				slog.Int64("resp_bytes", rec.bytes),
				slog.Duration("dur", time.Since(start)),
			}
			if rec.code != "" {
				attrs = append(attrs, slog.String("code", rec.code))
			}
			if len(rec.attrs) > 0 {
				attrs = append(attrs, slog.Group("", rec.attrs...))
			}
			level := slog.LevelInfo
			if (route == "GET /healthz" && status == http.StatusOK) || (route == "GET /v1/mailbox" && status == http.StatusOK && emptyCollect(rec.attrs)) {
				// Health probes and long-polls that end empty are most of
				// the traffic and carry no information; at info level they
				// would dominate log volume (and cost) with always-on
				// collectors re-polling every 25 s.
				level = slog.LevelDebug
			}
			s.log.LogAttrs(r.Context(), level, "request", attrs...)
		}()
		next.ServeHTTP(rec, r)
	})
}

// withSecurityHeaders sets conservative response headers. The web
// documents (web.go) replace them with their own fuller set.
func withSecurityHeaders(hsts bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Robots-Tag", "noindex, nofollow")
		if hsts {
			h.Set("Strict-Transport-Security", hstsValue)
		}
		next.ServeHTTP(w, r)
	})
}

// clientIP returns the client address. With trustProxy, the LAST
// X-Forwarded-For entry is used: that is the hop appended by our own load
// balancer (AWS ALB appends the peer address it saw). Earlier entries are
// client-controlled and ignored.
func clientIP(r *http.Request, trustProxy bool) netip.Addr {
	if trustProxy {
		if xff := r.Header.Values("X-Forwarded-For"); len(xff) > 0 {
			last := xff[len(xff)-1]
			if i := strings.LastIndexByte(last, ','); i >= 0 {
				last = last[i+1:]
			}
			if a, err := netip.ParseAddr(strings.TrimSpace(last)); err == nil {
				return a.Unmap()
			}
		}
	}
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return ap.Addr().Unmap()
	}
	if a, err := netip.ParseAddr(r.RemoteAddr); err == nil {
		return a.Unmap()
	}
	return netip.Addr{}
}

// rateKey is the rate-limit key of a client network: the full IPv4 address
// or the IPv6 /64.
func rateKey(a netip.Addr) string {
	if !a.IsValid() {
		return "unknown"
	}
	if a.Is4() {
		return a.String()
	}
	p, _ := a.Prefix(64)
	return p.String()
}

// withIPRateLimit applies the per-network limits that come before anything
// else (tokens, signatures, bodies) is examined (spec §7.2, §8.5).
//
// /v1/: first the failed-authentication budget: a network that has used it
// up gets no unauthenticated work done, so only a request naming a key
// that authenticated from that network recently goes on (its signature is
// then checked first, authz.go). Reading one header and two map lookups
// are all that happens before that decision. Then the flood guard.
//
// Everything else (/connect, /.well-known/, /robots.txt and every unknown
// path): a separate web bucket, so scanners spend their own budget and
// never the mailbox traffic's (§6.11). /healthz is exempt so load-balancer
// probes never starve.
func (s *Server) withIPRateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case isAPIPath(r.URL.Path):
			addr := rateKey(clientIP(r, s.cfg.TrustProxy))
			st := stateOf(w)
			if e := s.penalty(addr); e != nil {
				st.penalised = true
				k := headerKey(r)
				if k == "" || !s.known.Has(knownKey(addr, k), s.now()) {
					s.rl.refused.With(limAuthFail).Inc()
					s.writeError(w, e)
					return
				}
			}
			if e := s.take(limAddress, s.addrLimit, addr, true); e != nil {
				s.writeError(w, e)
				return
			}
			st.addr = addr
		case r.URL.Path != "/healthz":
			if e := s.take(limWeb, s.webLimit, rateKey(clientIP(r, s.cfg.TrustProxy)), false); e != nil {
				s.writeError(w, e)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// emptyCollect reports whether a collect response delivered no messages.
func emptyCollect(attrs []any) bool {
	for i := 0; i+1 < len(attrs); i += 2 {
		if attrs[i] == "count" {
			n, ok := attrs[i+1].(int)
			return ok && n == 0
		}
	}
	return false
}
