package dynamo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"syscall"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
)

// Errors from the AWS clients are scrubbed where they enter the store.
// Their text can name what was asked for: a transport failure prints the
// request's URL, and an S3 object key holds the mailbox id
// (blobs/<mailbox>/<blob>); an access error can name a resource ARN. The
// store's errors reach the logs, which carry only msg_ids, sizes and
// error codes (RELAY-PROTOCOL §8). A scrubbed error's text is the
// service, the operation and what went wrong as a code (the AWS error
// code, a transaction's cancellation reasons, a system call's error, a
// context's end, or the innermost error's type); the original stays
// reachable through Unwrap, so errors.Is and errors.As still work.
//
// The layers beneath an awsError still hold the SDK's text, URL and all.
// Nothing may print them: log an error's Error() only, never a walk of its
// chain (a handler or reporter that prints every wrapped error would put
// the mailbox ids back in the logs).

// awsError is a scrubbed AWS client error.
type awsError struct {
	text string
	err  error
}

func (e *awsError) Error() string { return e.text }
func (e *awsError) Unwrap() error { return e.err }

// scrub returns err with its text reduced as described above (nil for
// nil).
func scrub(service, op string, err error) error {
	if err == nil {
		return nil
	}
	var (
		tce   *types.TransactionCanceledException
		api   smithy.APIError
		errno syscall.Errno
	)
	var what string
	switch {
	case errors.As(err, &tce):
		codes := make([]string, len(tce.CancellationReasons))
		for i := range tce.CancellationReasons {
			codes[i] = reasonCode(tce.CancellationReasons, i)
			if codes[i] == "" {
				codes[i] = "None"
			}
		}
		what = "TransactionCanceledException [" + strings.Join(codes, " ") + "]"
	case errors.As(err, &api):
		what = api.ErrorCode()
	case errors.Is(err, context.Canceled):
		what = "context canceled"
	case errors.Is(err, context.DeadlineExceeded):
		what = "context deadline exceeded"
	case errors.As(err, &errno):
		what = "transport: " + errno.Error()
	case errors.Is(err, io.ErrUnexpectedEOF):
		what = "transport: unexpected EOF"
	case errors.Is(err, io.EOF):
		what = "transport: connection closed"
	default:
		inner := err
		for u := errors.Unwrap(inner); u != nil; u = errors.Unwrap(inner) {
			inner = u
		}
		what = fmt.Sprintf("%T", inner)
	}
	return &awsError{text: service + " " + op + ": " + what, err: err}
}

// scrubDB is a DB whose errors are scrubbed.
type scrubDB struct{ db DB }

func (d scrubDB) GetItem(ctx context.Context, in *dynamodb.GetItemInput, o ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	out, err := d.db.GetItem(ctx, in, o...)
	return out, scrub("dynamodb", "GetItem", err)
}

func (d scrubDB) PutItem(ctx context.Context, in *dynamodb.PutItemInput, o ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	out, err := d.db.PutItem(ctx, in, o...)
	return out, scrub("dynamodb", "PutItem", err)
}

func (d scrubDB) UpdateItem(ctx context.Context, in *dynamodb.UpdateItemInput, o ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	out, err := d.db.UpdateItem(ctx, in, o...)
	return out, scrub("dynamodb", "UpdateItem", err)
}

func (d scrubDB) DeleteItem(ctx context.Context, in *dynamodb.DeleteItemInput, o ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
	out, err := d.db.DeleteItem(ctx, in, o...)
	return out, scrub("dynamodb", "DeleteItem", err)
}

func (d scrubDB) Query(ctx context.Context, in *dynamodb.QueryInput, o ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	out, err := d.db.Query(ctx, in, o...)
	return out, scrub("dynamodb", "Query", err)
}

func (d scrubDB) BatchGetItem(ctx context.Context, in *dynamodb.BatchGetItemInput, o ...func(*dynamodb.Options)) (*dynamodb.BatchGetItemOutput, error) {
	out, err := d.db.BatchGetItem(ctx, in, o...)
	return out, scrub("dynamodb", "BatchGetItem", err)
}

func (d scrubDB) BatchWriteItem(ctx context.Context, in *dynamodb.BatchWriteItemInput, o ...func(*dynamodb.Options)) (*dynamodb.BatchWriteItemOutput, error) {
	out, err := d.db.BatchWriteItem(ctx, in, o...)
	return out, scrub("dynamodb", "BatchWriteItem", err)
}

func (d scrubDB) TransactWriteItems(ctx context.Context, in *dynamodb.TransactWriteItemsInput, o ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error) {
	out, err := d.db.TransactWriteItems(ctx, in, o...)
	return out, scrub("dynamodb", "TransactWriteItems", err)
}

// scrubObjects is an Objects whose errors are scrubbed.
type scrubObjects struct{ o Objects }

func (x scrubObjects) PutObject(ctx context.Context, in *s3.PutObjectInput, o ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	out, err := x.o.PutObject(ctx, in, o...)
	return out, scrub("s3", "PutObject", err)
}

func (x scrubObjects) GetObject(ctx context.Context, in *s3.GetObjectInput, o ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	out, err := x.o.GetObject(ctx, in, o...)
	if err == nil && out != nil && out.Body != nil {
		out.Body = scrubBody{rc: out.Body}
	}
	return out, scrub("s3", "GetObject", err)
}

func (x scrubObjects) DeleteObject(ctx context.Context, in *s3.DeleteObjectInput, o ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	out, err := x.o.DeleteObject(ctx, in, o...)
	return out, scrub("s3", "DeleteObject", err)
}

// scrubBody scrubs the errors of an object's body as it is read (a
// connection that fails mid-body).
type scrubBody struct{ rc io.ReadCloser }

func (b scrubBody) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	if err == nil || err == io.EOF {
		return n, err
	}
	return n, scrub("s3", "GetObject body", err)
}

func (b scrubBody) Close() error { return scrub("s3", "GetObject body", b.rc.Close()) }
