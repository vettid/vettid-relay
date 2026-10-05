package api

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"strconv"
	"strings"
)

// Web endpoints (spec §6.11): fixed documents served to browsers and to
// Android's App Links verifier. Each is built once at startup and served
// byte-for-byte the same to every request: nothing in a response depends on
// the request (path variants, query, headers or cookies) except the method
// and If-None-Match. Invitation links carry their payload in the URL
// fragment, which browsers never send, so the relay never sees it.

//go:embed web/connect.html
var connectHTML []byte

//go:embed web/robots.txt
var robotsTXT []byte

const (
	pathConnect    = "/connect"
	pathAssetLinks = "/.well-known/assetlinks.json"
	pathRobots     = "/robots.txt"

	// webCacheControl lets browsers and shared caches keep a document for a
	// day without revalidating; the strong ETag makes revalidation cheap.
	webCacheControl = "public, max-age=86400, immutable"

	// webPermissionsPolicy denies the powerful features a page could ask
	// for. clipboard-write stays at its default (self) for the copy button.
	webPermissionsPolicy = "accelerometer=(), autoplay=(), camera=(), " +
		"display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), hid=(), " +
		"idle-detection=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), " +
		"publickey-credentials-get=(), screen-wake-lock=(), serial=(), usb=(), xr-spatial-tracking=()"

	// webDataCSP is the policy for non-HTML documents: nothing may load.
	webDataCSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; sandbox"
)

// staticDoc is one fixed web document with its precomputed headers.
type staticDoc struct {
	body    []byte
	etag    string
	headers [][2]string // headers on every response (200, 304 and 405)
	content [][2]string // headers on 200 and 304
}

// newStaticDoc precomputes the headers of a document.
func newStaticDoc(body []byte, contentType, csp string, hsts bool) *staticDoc {
	sum := sha256.Sum256(body)
	d := &staticDoc{body: body, etag: `"` + hex.EncodeToString(sum[:16]) + `"`}
	d.headers = [][2]string{
		{"Content-Security-Policy", csp},
		{"X-Content-Type-Options", "nosniff"},
		{"X-Frame-Options", "DENY"},
		{"Referrer-Policy", "no-referrer"},
		{"Permissions-Policy", webPermissionsPolicy},
		{"Cross-Origin-Opener-Policy", "same-origin"},
		{"Cross-Origin-Resource-Policy", "same-origin"},
		{"X-Robots-Tag", "noindex, nofollow"},
	}
	if hsts {
		d.headers = append(d.headers, [2]string{"Strict-Transport-Security", hstsValue})
	}
	d.content = [][2]string{
		{"Content-Type", contentType},
		{"Cache-Control", webCacheControl},
		{"ETag", d.etag},
	}
	return d
}

// serve answers GET and HEAD with the document (or 304 when If-None-Match
// matches) and anything else with an empty 405. Range is not supported:
// a ranged GET gets the whole document.
func (d *staticDoc) serve(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Del("Cache-Control")
	for _, kv := range d.headers {
		h.Set(kv[0], kv[1])
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		h.Set("Allow", "GET, HEAD")
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Length", "0")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	for _, kv := range d.content {
		h.Set(kv[0], kv[1])
	}
	if etagMatch(r.Header.Values("If-None-Match"), d.etag) {
		h.Del("Content-Type")
		w.WriteHeader(http.StatusNotModified)
		return
	}
	h.Set("Content-Length", strconv.Itoa(len(d.body)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		w.Write(d.body)
	}
}

// etagMatch reports whether any If-None-Match header value lists etag or
// "*". Comparison is weak (RFC 9110 §13.1.2): a W/ prefix is ignored.
func etagMatch(values []string, etag string) bool {
	for _, v := range values {
		for len(v) > 0 {
			v = strings.TrimLeft(v, " \t,")
			if v == "" {
				break
			}
			if v[0] == '*' {
				return true
			}
			v = strings.TrimPrefix(v, "W/")
			if v == "" || v[0] != '"' {
				return false // malformed: never matches
			}
			end := strings.IndexByte(v[1:], '"')
			if end < 0 {
				return false
			}
			if v[:end+2] == etag {
				return true
			}
			v = v[end+2:]
		}
	}
	return false
}

// webDocs holds the documents this relay serves.
type webDocs struct {
	connect    *staticDoc
	robots     *staticDoc
	assetLinks *staticDoc // nil when no fingerprints are configured
	connectCSP string
}

// hstsValue is sent when the relay's public base URL is https.
const hstsValue = "max-age=31536000"

// newWebDocs builds the web documents for this configuration.
func newWebDocs(androidPackage string, fingerprints []string, hsts bool) (*webDocs, error) {
	csp, err := connectCSP(connectHTML)
	if err != nil {
		return nil, err
	}
	wd := &webDocs{
		connect:    newStaticDoc(connectHTML, "text/html; charset=utf-8", csp, hsts),
		robots:     newStaticDoc(robotsTXT, "text/plain; charset=utf-8", webDataCSP, hsts),
		connectCSP: csp,
	}
	if len(fingerprints) > 0 {
		body, err := assetLinksJSON(androidPackage, fingerprints)
		if err != nil {
			return nil, err
		}
		wd.assetLinks = newStaticDoc(body, "application/json", webDataCSP, hsts)
	}
	return wd, nil
}

// assetLinksJSON is the Digital Asset Links statement list letting the
// Android app handle this relay's links.
func assetLinksJSON(pkg string, fingerprints []string) ([]byte, error) {
	type target struct {
		Namespace    string   `json:"namespace"`
		PackageName  string   `json:"package_name"`
		Fingerprints []string `json:"sha256_cert_fingerprints"`
	}
	type statement struct {
		Relation []string `json:"relation"`
		Target   target   `json:"target"`
	}
	b, err := json.MarshalIndent([]statement{{
		Relation: []string{"delegate_permission/common.handle_all_urls"},
		Target:   target{Namespace: "android_app", PackageName: pkg, Fingerprints: fingerprints},
	}}, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// connectCSP builds the /connect policy: nothing may load, except the
// page's one inline <style> and one inline <script>, allowed by hash.
func connectCSP(page []byte) (string, error) {
	style, err := inlineElement(page, "style")
	if err != nil {
		return "", err
	}
	script, err := inlineElement(page, "script")
	if err != nil {
		return "", err
	}
	return "default-src 'none'; script-src " + cspHash(script) + "; style-src " + cspHash(style) +
		"; img-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'", nil
}

// inlineElement returns the text of the page's only <tag>…</tag> element.
func inlineElement(page []byte, tag string) ([]byte, error) {
	open, closing := []byte("<"+tag+">"), []byte("</"+tag+">")
	if bytes.Count(page, []byte("<"+tag)) != 1 || bytes.Count(page, open) != 1 || bytes.Count(page, closing) != 1 {
		return nil, fmt.Errorf("connect page: want exactly one plain <%s> element", tag)
	}
	start := bytes.Index(page, open) + len(open)
	end := bytes.Index(page, closing)
	if end < start {
		return nil, fmt.Errorf("connect page: malformed <%s> element", tag)
	}
	return page[start:end], nil
}

// cspHash is the CSP source expression for an inline element's text.
func cspHash(text []byte) string {
	sum := sha256.Sum256(text)
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

// webRoutes registers the web documents at their exact paths.
func (s *Server) webRoutes() {
	s.mux.HandleFunc(pathConnect, s.exactDoc(pathConnect, s.web.connect))
	s.mux.HandleFunc(pathRobots, s.exactDoc(pathRobots, s.web.robots))
	if s.web.assetLinks != nil {
		s.mux.HandleFunc(pathAssetLinks, s.exactDoc(pathAssetLinks, s.web.assetLinks))
	}
}

// exactDoc serves d only when the request's escaped path is exactly p (so
// that percent-encoded spellings get the ordinary 404, like every other
// variant).
func (s *Server) exactDoc(p string, d *staticDoc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != p {
			s.writeError(w, fail(CodeNotFound))
			return
		}
		d.serve(w, r)
	}
}

// canonicalPath reports whether p is already in the form ServeMux would
// redirect to. The relay never redirects: non-canonical paths get the
// ordinary 404 instead (spec §6.11).
func canonicalPath(p string) bool {
	if p == "" || p[0] != '/' {
		return false
	}
	np := path.Clean(p)
	if p[len(p)-1] == '/' && np != "/" {
		np += "/"
	}
	return np == p
}

// isAPIPath reports whether the per-IP API limiter (not the web limiter)
// applies to p.
func isAPIPath(p string) bool { return strings.HasPrefix(p, "/v1/") }
