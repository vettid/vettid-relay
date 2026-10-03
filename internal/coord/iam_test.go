package coord

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/credentials"
)

func TestIAMToken(t *testing.T) {
	cfg := Config{
		IAMUser: "relay", CacheName: "Vettid-Org-Relay", Serverless: true, Region: "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider("AKIDEXAMPLE", "secret", "session"),
	}
	tok, err := iamToken(context.Background(), cfg, time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(tok, "http") || !strings.HasPrefix(tok, "vettid-org-relay/?") {
		t.Fatalf("token must be host/?query without scheme, lowercase cache name: %s", tok)
	}
	q, err := url.ParseQuery(strings.SplitN(tok, "?", 2)[1])
	if err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{
		"Action": "connect", "User": "relay", "ResourceType": "ServerlessCache",
		"X-Amz-Expires": "900", "X-Amz-Algorithm": "AWS4-HMAC-SHA256", "X-Amz-Security-Token": "session",
		"X-Amz-Credential": "AKIDEXAMPLE/20261003/us-east-1/elasticache/aws4_request",
	} {
		if q.Get(k) != want {
			t.Errorf("%s = %q, want %q", k, q.Get(k), want)
		}
	}
	if len(q.Get("X-Amz-Signature")) != 64 {
		t.Error("missing signature")
	}
}
