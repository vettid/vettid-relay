package main

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/vettid/vettid-relay/internal/config"
	"github.com/vettid/vettid-relay/internal/coord"
	"github.com/vettid/vettid-relay/internal/metrics"
	"github.com/vettid/vettid-relay/internal/store"
	"github.com/vettid/vettid-relay/internal/store/dynamo"
)

// openStore opens the configured backend. SQLite creates the database file
// in WAL mode before the relay listens; DynamoDB is checked with one read.
func openStore(ctx context.Context, cfg config.Config) (store.Backend, error) {
	if cfg.Store != "dynamodb" {
		return store.Open(ctx, cfg.DBPath)
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws config: %w", err)
	}
	db := dynamodb.NewFromConfig(awsCfg, func(o *dynamodb.Options) {
		if cfg.DynamoEndpoint != "" {
			o.BaseEndpoint = aws.String(cfg.DynamoEndpoint)
		}
	})
	var objects dynamo.Objects
	if cfg.BlobsEnabled {
		objects = s3.NewFromConfig(awsCfg, func(o *s3.Options) {
			if cfg.S3Endpoint != "" {
				o.BaseEndpoint = aws.String(cfg.S3Endpoint)
				o.UsePathStyle = true
				o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
				o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
			}
		})
	}
	st, err := dynamo.New(dynamo.Config{
		Table: cfg.DynamoTable, Bucket: cfg.BlobBucket, DB: db, S3: objects,
		// A rotated-away mailbox must stop resolving when its grace ends.
		MailboxCacheTTL: min(5*time.Minute, cfg.RotationGrace/2),
	})
	if err != nil {
		return nil, err
	}
	if err := st.Ping(ctx); err != nil {
		return nil, fmt.Errorf("dynamodb table %s: %w", cfg.DynamoTable, err)
	}
	return st, nil
}

// openCoord connects to Valkey (IAM-authenticated on ElastiCache).
func openCoord(ctx context.Context, cfg config.Config, reg *metrics.Registry) (*coord.Client, error) {
	cc := coord.Config{Addr: cfg.ValkeyAddr, TLS: cfg.ValkeyTLS, Prefix: cfg.ValkeyPrefix}
	if cfg.ValkeyIAMUser != "" {
		awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
		if err != nil {
			return nil, fmt.Errorf("aws config: %w", err)
		}
		cc.IAMUser, cc.CacheName, cc.Serverless = cfg.ValkeyIAMUser, cfg.ValkeyCacheName, cfg.ValkeyServerless
		cc.Region, cc.Credentials = awsCfg.Region, awsCfg.Credentials
	}
	return coord.Open(ctx, cc, reg)
}
