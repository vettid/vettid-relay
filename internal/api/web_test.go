package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/vettid/vettid-relay/internal/config"
)

// webResp is one raw response, redirects never followed.
type webResp struct {
	status int
	header http.Header
	body   []byte
}

var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func (f *fixture) web(method, path string, hdr http.Header) webResp {
	f.t.Helper()
	hr, err := http.NewRequest(method, f.ts.URL+path, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	for k, v := range hdr {
		hr.Header[k] = v
	}
	resp, err := noRedirect.Do(hr)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	resp.Header.Del("Date") // the only header allowed to vary
	return webResp{resp.StatusCode, resp.Header, b}
}

func sameResp(a, b webResp) bool {
	if a.status != b.status || !bytes.Equal(a.body, b.body) || len(a.header) != len(b.header) {
		return false
	}
	for k, v := range a.header {
		if !slices.Equal(v, b.header[k]) {
			return false
		}
	}
	return true
}

func TestConnectPageHeaders(t *testing.T) {
	f := newFixture(t, nil)
	r := f.web("GET", "/connect", nil)
	if r.status != 200 || !bytes.Equal(r.body, connectHTML) {
		t.Fatalf("GET /connect: %d (%d bytes)", r.status, len(r.body))
	}
	want := map[string]string{
		"Content-Type":                 "text/html; charset=utf-8",
		"Cache-Control":                webCacheControl,
		"Etag":                         f.s.web.connect.etag,
		"Content-Security-Policy":      f.s.web.connectCSP,
		"X-Content-Type-Options":       "nosniff",
		"X-Frame-Options":              "DENY",
		"Referrer-Policy":              "no-referrer",
		"Permissions-Policy":           webPermissionsPolicy,
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
		"X-Robots-Tag":                 "noindex, nofollow",
		"Strict-Transport-Security":    hstsValue, // the fixture's base URL is https
	}
	for k, v := range want {
		if got := r.header.Values(k); len(got) != 1 || got[0] != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	for _, k := range []string{"Set-Cookie", "Vary", "Location", "Last-Modified", "Accept-Ranges"} {
		if r.header.Get(k) != "" {
			t.Errorf("unexpected %s", k)
		}
	}
	if len(r.header) != len(want)+1 { // + Content-Length
		t.Errorf("unexpected header set: %v", r.header)
	}
	for _, d := range []string{"default-src 'none'", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'none'"} {
		if !strings.Contains(f.s.web.connectCSP, d) {
			t.Errorf("CSP lacks %s", d)
		}
	}
	if strings.Contains(f.s.web.connectCSP, "unsafe") || strings.Contains(f.s.web.connectCSP, "http") {
		t.Errorf("CSP too loose: %s", f.s.web.connectCSP)
	}
	if !strings.HasPrefix(f.s.web.connect.etag, `"`) || len(f.s.web.connect.etag) != 34 {
		t.Errorf("etag %s", f.s.web.connect.etag)
	}
}

// Every request gets the same bytes: no reflection of query, path,
// headers or cookies, in the body or the headers.
func TestConnectSameBytesForEveryRequest(t *testing.T) {
	f := newFixtureLog(t, func(c *config.Config) { c.TrustProxy = true }, io.Discard)
	base := f.web("GET", "/connect", nil)
	variants := []struct {
		path string
		hdr  http.Header
	}{
		{"/connect?x=MARKERQ", nil},
		{"/connect?", nil},
		{"/connect?link=MARKERQ&a=b#frag", nil},
		{"/connect", http.Header{"Referer": {"https://example.net/MARKERR"}}},
		{"/connect", http.Header{"User-Agent": {"MARKERUA"}, "Accept-Language": {"fr"}, "Accept": {"application/json"}}},
		{"/connect", http.Header{"Cookie": {"s=MARKERC"}, "X-Forwarded-For": {"203.0.113.9"}, "X-Forwarded-Host": {"MARKERH"}}},
		{"/connect", http.Header{"Range": {"bytes=0-10"}, "If-Modified-Since": {"Mon, 01 Jan 2024 00:00:00 GMT"}}},
		{"/connect", http.Header{"If-None-Match": {`"nope"`}, "Origin": {"https://MARKERO"}}},
	}
	for _, v := range variants {
		r := f.web("GET", v.path, v.hdr)
		if !sameResp(base, r) {
			t.Errorf("%s %v: response differs: %d %v", v.path, v.hdr, r.status, r.header)
		}
		all, _ := json.Marshal(r.header)
		if bytes.Contains(r.body, []byte("MARKER")) || bytes.Contains(all, []byte("MARKER")) {
			t.Errorf("%s: request content reflected", v.path)
		}
	}
	// HEAD: the same headers, no body.
	h := f.web("HEAD", "/connect?x=1", nil)
	if h.status != 200 || len(h.body) != 0 || h.header.Get("Content-Length") != base.header.Get("Content-Length") {
		t.Fatalf("HEAD: %d %v", h.status, h.header)
	}
	h.body = base.body
	if !sameResp(base, h) {
		t.Fatalf("HEAD headers differ: %v", h.header)
	}
}

func TestConnectConditional(t *testing.T) {
	f := newFixture(t, nil)
	etag := f.s.web.connect.etag
	for _, inm := range []string{etag, "W/" + etag, "*", `"other", ` + etag, `"a","b",W/` + etag} {
		r := f.web("GET", "/connect", http.Header{"If-None-Match": {inm}})
		if r.status != http.StatusNotModified || len(r.body) != 0 || r.header.Get("Etag") != etag || r.header.Get("Cache-Control") != webCacheControl {
			t.Errorf("If-None-Match %s: %d %v", inm, r.status, r.header)
		}
	}
	for _, inm := range []string{`"other"`, "garbage", etag[:10], `W/"x"`} {
		if r := f.web("GET", "/connect", http.Header{"If-None-Match": {inm}}); r.status != 200 {
			t.Errorf("If-None-Match %s: %d", inm, r.status)
		}
	}
}

func TestWebMethods(t *testing.T) {
	f := newFixture(t, nil)
	for _, p := range []string{"/connect", "/.well-known/assetlinks.json", "/robots.txt"} {
		for _, m := range []string{"POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "PROPFIND"} {
			r := f.web(m, p+"?q=1", nil)
			if r.status != http.StatusMethodNotAllowed || len(r.body) != 0 || r.header.Get("Allow") != "GET, HEAD" ||
				r.header.Get("Content-Type") != "" || r.header.Get("Etag") != "" || r.header.Get("X-Frame-Options") != "DENY" {
				t.Errorf("%s %s: %d %q %v", m, p, r.status, r.body, r.header)
			}
		}
	}
}

// Only the exact paths serve; every variant gets the relay's ordinary 404,
// byte-for-byte, and nothing redirects.
func TestWebVariantsAreOrdinary404s(t *testing.T) {
	f := newFixture(t, nil)
	ref := f.web("GET", "/nope", nil)
	if ref.status != 404 {
		t.Fatalf("reference 404: %d", ref.status)
	}
	for _, p := range []string{
		"/connect/", "/connect/x", "/connect/.", "/connect/..", "/Connect", "/CONNECT", "//connect", "/./connect",
		"/x/../connect", "/%63onnect", "/connect%2F", "/connect%2f", "/connect.html", "/connect;x", "/connect%00",
		"/connectx", "/connect/?x=1", "/.well-known/", "/.well-known", "/.well-known/assetlinks.json/",
		"/.well-known/./assetlinks.json", "/.well-known/apple-app-site-association", "/.well-known/security.txt",
		"/robots.txt/", "/v1//mailbox", "/v1/../connect", "/favicon.ico", "/index.html", "/",
	} {
		r := f.web("GET", p, nil)
		if !sameResp(ref, r) {
			t.Errorf("%s: %d %q %v", p, r.status, r.body, r.header)
		}
	}
}

func TestConnectInlineHashesAndContent(t *testing.T) {
	page := string(connectHTML)
	scripts := regexp.MustCompile(`(?is)<script\b[^>]*>(.*?)</script>`).FindAllStringSubmatch(page, -1)
	styles := regexp.MustCompile(`(?is)<style\b[^>]*>(.*?)</style>`).FindAllStringSubmatch(page, -1)
	if len(scripts) != 1 || len(styles) != 1 {
		t.Fatalf("want one inline script and one inline style, got %d, %d", len(scripts), len(styles))
	}
	csp := func(s string) string {
		sum := sha256.Sum256([]byte(s))
		return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	}
	f := newFixture(t, nil)
	got := f.web("GET", "/connect", nil).header.Get("Content-Security-Policy")
	want := "default-src 'none'; script-src " + csp(scripts[0][1]) + "; style-src " + csp(styles[0][1]) +
		"; img-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
	if got != want {
		t.Fatalf("CSP\n got %s\nwant %s", got, want)
	}
	// Nothing that needs more than the hashed inline blocks, and nothing
	// that could send the fragment anywhere.
	lower := strings.ToLower(page)
	for _, bad := range []string{
		" style=", "src=", "<img", "<iframe", "<object", "<embed", "<form", "<base", "<meta http-equiv",
		"@import", "url(", "http://", "fetch(", "xmlhttprequest", "sendbeacon", "websocket", "eventsource", "import(",
		"innerhtml", "outerhtml", "insertadjacenthtml", "eval(", "function(\"", "document.write", "document.cookie",
		"localstorage", "sessionstorage", "indexeddb", "window.open", "location.href =", "location.assign", "location.replace",
		"postmessage", "<link rel=\"stylesheet", "<link rel=\"preload", "<link rel=\"prefetch", "<link rel=\"dns-prefetch",
	} {
		if strings.Contains(lower, bad) {
			t.Errorf("page contains %q", bad)
		}
	}
	if m := regexp.MustCompile(`\son[a-z]+\s*=`).FindString(lower); m != "" {
		t.Errorf("page has an inline event handler %q", m)
	}
	if n := strings.Count(lower, "https://"); n != 1 || !strings.Contains(page, `href="https://vettid.org" rel="noreferrer noopener"`) {
		t.Errorf("only the plain vettid.org link may be absolute (%d)", n)
	}
	if strings.Count(lower, "<link") != 1 || !strings.Contains(page, `<link rel="icon" href="data:,">`) {
		t.Error("only the empty favicon link is allowed (it stops the default /favicon.ico fetch)")
	}
	for _, need := range []string{"Open this link in the VettID app", "vettid://connect#", "location.hash", `<meta name="referrer" content="no-referrer">`} {
		if !strings.Contains(page, need) {
			t.Errorf("page lacks %q", need)
		}
	}
}

func TestInlineElementRejectsAmbiguousPages(t *testing.T) {
	for _, p := range []string{
		"<style>a</style>",
		"<style>a</style><script>b</script><script>c</script>",
		"<style>a</style><script src=x></script>",
		"<style>a</style><script>b",
	} {
		if _, err := connectCSP([]byte(p)); err == nil {
			t.Errorf("%q accepted", p)
		}
	}
}

func TestAssetLinksDefault(t *testing.T) {
	f := newFixture(t, nil)
	r := f.web("GET", "/.well-known/assetlinks.json?x=1", http.Header{"Referer": {"https://x"}})
	if r.status != 200 || r.header.Get("Content-Type") != "application/json" || r.header.Get("Cache-Control") != webCacheControl ||
		r.header.Get("Etag") == "" || r.header.Get("Content-Security-Policy") != webDataCSP || r.header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("%d %v", r.status, r.header)
	}
	var st []struct {
		Relation []string `json:"relation"`
		Target   struct {
			Namespace    string   `json:"namespace"`
			PackageName  string   `json:"package_name"`
			Fingerprints []string `json:"sha256_cert_fingerprints"`
		} `json:"target"`
	}
	if err := json.Unmarshal(r.body, &st); err != nil {
		t.Fatal(err)
	}
	if len(st) != 1 || !slices.Equal(st[0].Relation, []string{"delegate_permission/common.handle_all_urls"}) ||
		st[0].Target.Namespace != "android_app" || st[0].Target.PackageName != "com.vettid.app" {
		t.Fatalf("%s", r.body)
	}
	want := []string{
		"31:A1:96:13:AA:10:F2:09:E0:89:45:F9:47:F9:4F:7C:E3:E6:E5:AC:34:24:57:FF:99:69:A6:79:86:92:8E:65",
		"BD:83:A0:75:3F:AA:6A:F6:F8:D8:1B:9F:76:A0:4A:C1:A4:99:EA:6C:7F:46:C6:F1:11:3D:4B:57:87:EC:B2:C4",
		"2F:ED:27:B7:27:46:79:7A:93:1F:D4:14:FF:3D:AC:4C:D9:69:FA:0C:2F:F3:62:09:AE:05:36:5F:58:00:14:F2",
	}
	if !slices.Equal(st[0].Target.Fingerprints, want) {
		t.Fatalf("fingerprints %v", st[0].Target.Fingerprints)
	}
	if again := f.web("GET", "/.well-known/assetlinks.json", nil); !sameResp(r, again) {
		t.Fatal("assetlinks differs between requests")
	}
	robots := f.web("GET", "/robots.txt?x", nil)
	if robots.status != 200 || string(robots.body) != "User-agent: *\nAllow: /.well-known/\nDisallow: /\n" || robots.header.Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Fatalf("robots: %d %q %v", robots.status, robots.body, robots.header)
	}
}

func TestAssetLinksConfigurable(t *testing.T) {
	cfg, err := config.Load(func(k string) (string, bool) {
		v, ok := map[string]string{
			"RELAY_ANDROID_PACKAGE":     "org.example.relayapp",
			"RELAY_ANDROID_CERT_SHA256": "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
		}[k]
		return v, ok
	})
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, func(c *config.Config) {
		c.AndroidPackage, c.AndroidCertFingerprints = cfg.AndroidPackage, cfg.AndroidCertFingerprints
	})
	r := f.web("GET", "/.well-known/assetlinks.json", nil)
	if r.status != 200 || !bytes.Contains(r.body, []byte(`"package_name": "org.example.relayapp"`)) ||
		!bytes.Contains(r.body, []byte(`"AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"`)) ||
		bytes.Contains(r.body, []byte("31:A1")) {
		t.Fatalf("%d %s", r.status, r.body)
	}

	// An empty list turns assetlinks.json off: the ordinary 404.
	off := newFixture(t, func(c *config.Config) { c.AndroidCertFingerprints = nil })
	if r, ref := off.web("GET", "/.well-known/assetlinks.json", nil), off.web("GET", "/nope", nil); !sameResp(r, ref) {
		t.Fatalf("disabled assetlinks: %d %s", r.status, r.body)
	}
	if r := off.web("GET", "/connect", nil); r.status != 200 {
		t.Fatalf("connect without assetlinks: %d", r.status)
	}
}

// The web bucket is per IP and separate from the API's: a scanner that
// exhausts it gets 429 on web paths and unknown paths only, and mailbox
// traffic is unaffected (and the other way round).
func TestWebRateLimitSeparateFromAPI(t *testing.T) {
	f := newFixture(t, func(c *config.Config) {
		c.RateWebPerSec, c.RateWebBurst = 0.01, 3
		c.RateIPPerSec, c.RateIPBurst = 0.01, 2
		c.TrustProxy = true
	})
	scanner := http.Header{"X-Forwarded-For": {"198.51.100.7"}}
	for i := 0; i < 3; i++ {
		if r := f.web("GET", "/connect", scanner); r.status != 200 {
			t.Fatalf("request %d: %d", i, r.status)
		}
	}
	for _, p := range []string{"/connect", "/.well-known/assetlinks.json", "/robots.txt", "/wp-login.php", "/connect/x"} {
		r := f.web("GET", p, scanner)
		var e errorBody
		json.Unmarshal(r.body, &e)
		if r.status != 429 || e.Code != CodeRateLimited || r.header.Get("Retry-After") == "" || r.header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: %d %s", p, r.status, r.body)
		}
	}
	// The same IP's API budget is untouched (401: unsigned, but not limited).
	for i := 0; i < 2; i++ {
		if r := f.web("GET", "/v1/mailbox", scanner); r.status == 429 {
			t.Fatalf("API request %d limited by the web bucket", i)
		}
	}
	if r := f.web("GET", "/v1/mailbox", scanner); r.status != 429 {
		t.Fatalf("API bucket: %d", r.status)
	}
	if r := f.web("GET", "/healthz", scanner); r.status != 200 {
		t.Fatalf("healthz: %d", r.status)
	}
	// Another client still gets the page; and an exhausted API bucket does
	// not touch the web one.
	other := http.Header{"X-Forwarded-For": {"198.51.100.8"}}
	f.web("GET", "/v1/mailbox", other)
	f.web("GET", "/v1/mailbox", other)
	if r := f.web("GET", "/v1/mailbox", other); r.status != 429 {
		t.Fatalf("other API bucket: %d", r.status)
	}
	if r := f.web("GET", "/connect", other); r.status != 200 {
		t.Fatalf("other client's page: %d", r.status)
	}
}

// Access logs carry the route pattern only: never the query, the raw path
// of a variant, the Referer or any other request header.
func TestWebLogsCarryNothingRequestSpecific(t *testing.T) {
	var logs syncBuf
	f := newFixtureLog(t, nil, &logs)
	hdr := http.Header{"Referer": {"https://example.net/LOGREF"}, "User-Agent": {"LOGUA"}, "Cookie": {"c=LOGCOOKIE"}}
	f.web("GET", "/connect?link=LOGQUERY", hdr)
	f.web("HEAD", "/connect?LOGQUERY2", hdr)
	f.web("POST", "/connect?LOGQUERY3", hdr)
	f.web("GET", "/connect/LOGPATH", hdr)
	f.web("GET", "//connect/LOGPATH2", hdr)
	f.web("GET", "/.well-known/assetlinks.json?LOGQUERY4", hdr)
	f.web("GET", "/.well-known/LOGPATH3", hdr)
	out := logs.String()
	if !strings.Contains(out, `"route":"/connect"`) || !strings.Contains(out, `"route":"/.well-known/assetlinks.json"`) || !strings.Contains(out, `"route":"unmatched"`) {
		t.Fatalf("expected route patterns in logs:\n%s", out)
	}
	for _, m := range []string{"LOG" + "QUERY", "LOGPATH", "LOGREF", "LOGUA", "LOGCOOKIE", "example.net", "?", "Referer", "referer"} {
		if strings.Contains(out, m) {
			t.Errorf("logs contain %q:\n%s", m, out)
		}
	}
}

func TestHSTSOnlyForHTTPSBaseURL(t *testing.T) {
	https := newFixture(t, nil)
	for _, p := range []string{"/connect", "/nope", "/healthz"} {
		if got := https.web("GET", p, nil).header.Get("Strict-Transport-Security"); got != hstsValue {
			t.Errorf("https %s: HSTS %q", p, got)
		}
	}
	plain := newFixture(t, func(c *config.Config) { c.BaseURL = "http://relay.home.arpa:8080" })
	for _, p := range []string{"/connect", "/nope"} {
		if got := plain.web("GET", p, nil).header.Get("Strict-Transport-Security"); got != "" {
			t.Errorf("http %s: HSTS %q", p, got)
		}
	}
}

func TestCanonicalPath(t *testing.T) {
	for p, want := range map[string]bool{
		"/": true, "/connect": true, "/v1/mailbox/": true, "/a/b": true,
		"": false, "connect": false, "//connect": false, "/./connect": false, "/a/../b": false, "/connect/.": false, "/a//": false,
	} {
		if canonicalPath(p) != want {
			t.Errorf("canonicalPath(%q) != %v", p, want)
		}
	}
}

func FuzzETagMatch(f *testing.F) {
	const etag = `"0123456789abcdef0123456789abcdef"`
	for _, s := range []string{etag, "W/" + etag, "*", `"a", ` + etag, `"a",W/"b"`, `W/`, `"`, `,,,`, `"a" "b"`, "", " \t" + etag} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, v string) {
		got := etagMatch([]string{v}, etag)
		if got && !strings.Contains(v, "*") && !strings.Contains(v, etag) {
			t.Fatalf("%q matched without the etag", v)
		}
		if v == etag && !got {
			t.Fatal("exact etag did not match")
		}
	})
}
