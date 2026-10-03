// Package ddblocal connects tests to DynamoDB Local (or any DynamoDB-
// compatible endpoint) named by RELAY_TEST_DYNAMODB_ENDPOINT, e.g.
//
//	make test-dynamo   # starts a memory-capped amazon/dynamodb-local
//
// Tests that need it are skipped when the variable is unset.
package ddblocal

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"github.com/vettid/vettid-relay/internal/store/dynamo"
)

// EnvEndpoint names the DynamoDB endpoint for tests.
const EnvEndpoint = "RELAY_TEST_DYNAMODB_ENDPOINT"

// Client returns a client for the test endpoint, skipping t if none is set.
func Client(t testing.TB) *dynamodb.Client {
	t.Helper()
	ep := os.Getenv(EnvEndpoint)
	if ep == "" {
		t.Skipf("%s not set (run `make test-dynamo`)", EnvEndpoint)
	}
	return dynamodb.New(dynamodb.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String(ep),
		Credentials:  credentials.NewStaticCredentialsProvider("local", "local", ""),
	})
}

// Table creates a fresh, uniquely named relay table, deleted after the test.
func Table(t testing.TB, db *dynamodb.Client) string {
	t.Helper()
	b := make([]byte, 6)
	rand.Read(b)
	name := "relay-test-" + hex.EncodeToString(b)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := dynamo.CreateTable(ctx, db, name); err != nil {
		t.Fatalf("create table: %v", err)
	}
	t.Cleanup(func() {
		db.DeleteTable(context.Background(), &dynamodb.DeleteTableInput{TableName: &name})
	})
	return name
}
