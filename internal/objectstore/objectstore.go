// Package objectstore is the little of an object store's own API Helios
// needs beside restic: list the account's buckets, add up what a bucket
// holds, and delete a bucket with every file version in it. restic does
// none of the three. It speaks Backblaze B2's native API and S3.
package objectstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Bucket is one bucket in the account.
type Bucket struct {
	Name string
	// ID is the store's own identifier, where it has one.
	ID string
}

// Usage is what a bucket holds, counting every version of every file: the
// bytes the store bills for.
type Usage struct {
	Bytes int64
	Files int64
	// LastWrite is the newest upload in the bucket; zero when it is empty.
	LastWrite time.Time
}

// Deleted is how far a bucket's deletion got.
type Deleted struct {
	Files int64
	Bytes int64
	// Bucket is true once the bucket itself is gone.
	Bucket bool
}

// ErrWrittenSince means a bucket holds a file uploaded after the time its
// deletion was allowed from. Someone still writes to it, so nothing more is
// deleted.
var ErrWrittenSince = errors.New("the bucket was written to after it was given up")

// ErrNoBucket means the account holds no bucket of that name.
var ErrNoBucket = errors.New("no such bucket")

// Store is one account in an object store.
type Store interface {
	// Account identifies the account the credentials reach, so a record
	// made against one account is never applied to another.
	Account(ctx context.Context) (string, error)
	// Buckets lists every bucket the credentials can see.
	Buckets(ctx context.Context) ([]Bucket, error)
	// Usage adds up every file version in a bucket.
	Usage(ctx context.Context, b Bucket) (Usage, error)
	// DeleteBucket deletes every file version and unfinished upload in a
	// bucket, then the bucket. It reads the whole bucket first and deletes
	// nothing, returning ErrWrittenSince, when any file was uploaded after
	// notWrittenSince; a zero time skips that check. It can be run again
	// after any failure: what is gone stays gone and the rest is deleted.
	DeleteBucket(ctx context.Context, b Bucket, notWrittenSince time.Time) (Deleted, error)
}

// Config is how to reach a store, as the storage integration holds it.
type Config struct {
	// Kind is "s3", or anything else for Backblaze B2.
	Kind string
	// Endpoint is the S3 endpoint. B2 needs none.
	Endpoint string
	KeyID    string
	Key      string
}

// New returns the store a storage integration points at.
func New(c Config) (Store, error) {
	if c.KeyID == "" || c.Key == "" {
		return nil, errors.New("storage credentials are not set")
	}
	if c.Kind == "s3" {
		return newS3(c)
	}
	return &b2{keyID: c.KeyID, key: c.Key, authURL: b2AuthURL, http: newHTTP(), wait: backoff}, nil
}

// requestTimeout bounds one request. A listing page or a delete is small;
// a store that takes longer than this is not answering.
const requestTimeout = 60 * time.Second

// responseLimit bounds a response body. A listing page of a thousand files
// is well under a megabyte.
const responseLimit = 32 << 20

// attempts is how often one request is tried when the store says it is
// busy. Backblaze answers 503 as a matter of course and expects a retry.
const attempts = 4

func newHTTP() *http.Client { return &http.Client{Timeout: requestTimeout} }

// backoff waits before the nth retry, or returns early with ctx's error.
func backoff(ctx context.Context, n int) error {
	t := time.NewTimer(time.Duration(1<<n) * time.Second)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// retryable reports whether a status means "try again", not "no".
func retryable(status int) bool {
	return status == http.StatusTooManyRequests || status == http.StatusRequestTimeout || status >= 500
}

func readBody(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, responseLimit+1))
	if err != nil {
		return nil, err
	}
	if len(body) > responseLimit {
		return nil, fmt.Errorf("response is larger than %d bytes", responseLimit)
	}
	return body, nil
}

// APIError is a refusal from the store.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	if e.Code == "" && e.Message == "" {
		return fmt.Sprintf("storage answered HTTP %d", e.Status)
	}
	return fmt.Sprintf("storage answered HTTP %d %s: %s", e.Status, e.Code, e.Message)
}
