package dynamo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"syscall"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

const mailboxMarker = "MBX0123MARKER"

// What a scrubbed error says, and that errors.Is / errors.As still see
// the original.
func TestScrub(t *testing.T) {
	transport := &smithy.OperationError{ServiceID: "S3", OperationName: "DeleteObject", Err: &smithyhttp.RequestSendError{
		Err: &url.Error{Op: "Delete", URL: "http://s3/b/blobs/" + mailboxMarker + "/BLOB?x-id=DeleteObject", Err: fmt.Errorf("dial tcp 127.0.0.1:1: connect: %w", syscall.ECONNREFUSED)},
	}}
	denied := &smithy.GenericAPIError{Code: "AccessDenied", Message: "not authorized on arn:aws:s3:::b/blobs/" + mailboxMarker + "/BLOB"}
	tce := &types.TransactionCanceledException{Message: aws.String("cancelled"), CancellationReasons: []types.CancellationReason{
		{Code: aws.String("ConditionalCheckFailed")}, {Code: aws.String("None")}, {},
	}}
	for _, c := range []struct {
		err  error
		want string
	}{
		{transport, "s3 DeleteObject: transport: connection refused"},
		{denied, "s3 DeleteObject: AccessDenied"},
		{&s3types.NoSuchKey{Message: aws.String("blobs/" + mailboxMarker)}, "s3 DeleteObject: NoSuchKey"},
		{tce, "s3 DeleteObject: TransactionCanceledException [ConditionalCheckFailed None None]"},
		{fmt.Errorf("op %s: %w", mailboxMarker, context.DeadlineExceeded), "s3 DeleteObject: context deadline exceeded"},
		{fmt.Errorf("op %s: %w", mailboxMarker, context.Canceled), "s3 DeleteObject: context canceled"},
		{fmt.Errorf("bad %s: %w", mailboxMarker, errors.New(mailboxMarker)), "s3 DeleteObject: *errors.errorString"},
	} {
		got := scrub("s3", "DeleteObject", c.err)
		if got.Error() != c.want || strings.Contains(got.Error(), mailboxMarker) {
			t.Errorf("scrub(%v) = %q, want %q", c.err, got, c.want)
		}
		if !errors.Is(got, c.err) {
			t.Errorf("scrub(%v) doesn't wrap the original", c.err)
		}
	}
	var nsk *s3types.NoSuchKey
	if !errors.As(scrub("s3", "GetObject", &s3types.NoSuchKey{}), &nsk) {
		t.Error("errors.As can't find NoSuchKey through the scrub")
	}
	if !isCCF(scrub("dynamodb", "PutItem", &types.ConditionalCheckFailedException{})) {
		t.Error("isCCF can't see through the scrub")
	}
	if r := txReasons(scrub("dynamodb", "TransactWriteItems", tce)); len(r) != 3 {
		t.Error("txReasons can't see through the scrub")
	}
	if scrub("s3", "PutObject", nil) != nil {
		t.Error("nil scrubbed to non-nil")
	}
}

// joinDistinct keeps the first of each distinct text, at most three.
func TestJoinDistinct(t *testing.T) {
	a, b, c, d := errors.New("a"), errors.New("b"), errors.New("c"), errors.New("d")
	got := joinDistinct([]error{a, errors.New("a"), b, a, c, d}).Error()
	if got != "a\nb\nc" {
		t.Fatalf("joinDistinct = %q", got)
	}
	if joinDistinct(nil) != nil {
		t.Fatal("joinDistinct of nothing isn't nil")
	}
}

// failingBody fails mid-read with an error naming what was read.
type failingBody struct{}

func (failingBody) Read([]byte) (int, error) {
	return 0, &url.Error{Op: "Get", URL: "http://s3/b/blobs/" + mailboxMarker + "/BLOB", Err: io.ErrUnexpectedEOF}
}
func (failingBody) Close() error { return errors.New("close " + mailboxMarker) }

// An object's body that fails as it is read is scrubbed too; its end
// (io.EOF) is passed through as is.
func TestScrubBody(t *testing.T) {
	out, err := scrubObjects{o: bodyObjects{}}.GetObject(context.Background(), &s3.GetObjectInput{})
	if err != nil {
		t.Fatal(err)
	}
	b := out.Body
	_, err = b.Read(make([]byte, 4))
	if err == nil || strings.Contains(err.Error(), mailboxMarker) || err.Error() != "s3 GetObject body: transport: unexpected EOF" {
		t.Fatalf("a failed body read: %v", err)
	}
	if err := b.Close(); err == nil || strings.Contains(err.Error(), mailboxMarker) {
		t.Fatalf("a failed body close: %v", err)
	}
	if _, err := (scrubBody{rc: io.NopCloser(strings.NewReader(""))}).Read(make([]byte, 4)); err != io.EOF {
		t.Fatalf("the body's end: %v, want io.EOF itself", err)
	}
}

// bodyObjects answers every GetObject with a failingBody.
type bodyObjects struct{ Objects }

func (bodyObjects) GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	return &s3.GetObjectOutput{Body: failingBody{}}, nil
}
