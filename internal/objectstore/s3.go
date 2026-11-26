package objectstore

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// s3DefaultRegion signs requests when the endpoint's name says nothing
// about a region. Self-hosted S3 servers accept it; a store that insists on
// another names it in its refusal, and the request is signed again.
const s3DefaultRegion = "us-east-1"

type s3 struct {
	keyID, key string
	// base is the endpoint without a trailing slash; buckets are addressed
	// by path under it, as restic addresses them.
	base   *url.URL
	region string
	http   *http.Client
	wait   func(context.Context, int) error
	now    func() time.Time

	// plain is set once the store has refused to list versions: it keeps
	// none, so its objects are everything a bucket holds.
	plain bool
}

func newS3(c Config) (*s3, error) {
	u, err := url.Parse(strings.TrimSuffix(c.Endpoint, "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.RawQuery != "" {
		return nil, errors.New("the s3 endpoint must be an http or https address")
	}
	return &s3{keyID: c.KeyID, key: c.Key, base: u, region: regionOf(u.Hostname()), http: newHTTP(), wait: backoff, now: time.Now}, nil
}

var regionInHost = regexp.MustCompile(`^s3[.-]([a-z0-9-]+)\.(amazonaws\.com|backblazeb2\.com|wasabisys\.com)$`)

// regionOf reads the region out of the endpoint names that carry one.
func regionOf(host string) string {
	if m := regionInHost.FindStringSubmatch(host); m != nil {
		return m[1]
	}
	if strings.HasSuffix(host, ".r2.cloudflarestorage.com") {
		return "auto"
	}
	return s3DefaultRegion
}

// escape encodes as SigV4 requires: everything but unreserved characters,
// and "/" too unless it separates path segments.
func escape(s string, keepSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == '/' && keepSlash:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func canonicalQuery(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		values := append([]string{}, q[k]...)
		sort.Strings(values)
		for _, v := range values {
			parts = append(parts, escape(k, false)+"="+escape(v, false))
		}
	}
	return strings.Join(parts, "&")
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// emptyPayload is the SHA-256 of no body. Every request here has none.
const emptyPayload = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// sign returns the Authorization header for a bodyless request, AWS
// Signature Version 4, signing the host, payload hash and date headers.
func sign(keyID, key, region, method, host, escapedPath, query string, at time.Time) string {
	stamp := at.UTC().Format("20060102T150405Z")
	day := stamp[:8]
	scope := day + "/" + region + "/s3/aws4_request"
	const signed = "host;x-amz-content-sha256;x-amz-date"
	request := strings.Join([]string{
		method, escapedPath, query,
		"host:" + host, "x-amz-content-sha256:" + emptyPayload, "x-amz-date:" + stamp, "",
		signed, emptyPayload,
	}, "\n")
	digest := sha256.Sum256([]byte(request))
	toSign := strings.Join([]string{"AWS4-HMAC-SHA256", stamp, scope, hex.EncodeToString(digest[:])}, "\n")
	k := hmacSHA256([]byte("AWS4"+key), day)
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, "s3")
	k = hmacSHA256(k, "aws4_request")
	return "AWS4-HMAC-SHA256 Credential=" + keyID + "/" + scope + ", SignedHeaders=" + signed + ", Signature=" + hex.EncodeToString(hmacSHA256(k, toSign))
}

type s3Refusal struct {
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
	Region  string `xml:"Region"`
}

// do runs one request against a path under the endpoint and decodes an XML
// answer into out.
func (c *s3) do(ctx context.Context, method, path string, q url.Values, out any) error {
	escaped := escape(strings.TrimSuffix(c.base.Path, "/")+path, true)
	query := canonicalQuery(q)
	var last error
	resigned := false
	for n := 0; n < attempts; n++ {
		if n > 0 && !resigned {
			if err := c.wait(ctx, n-1); err != nil {
				return errors.Join(last, err)
			}
		}
		resigned = false
		target := c.base.Scheme + "://" + c.base.Host + escaped
		if query != "" {
			target += "?" + query
		}
		req, err := http.NewRequestWithContext(ctx, method, target, nil)
		if err != nil {
			return err
		}
		at := c.now()
		req.Header.Set("x-amz-date", at.UTC().Format("20060102T150405Z"))
		req.Header.Set("x-amz-content-sha256", emptyPayload)
		req.Header.Set("Authorization", sign(c.keyID, c.key, c.region, method, c.base.Host, escaped, query, at))
		resp, err := c.http.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return err
			}
			last = err
			continue
		}
		body, err := readBody(resp)
		if err != nil {
			last = err
			continue
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if out == nil || len(body) == 0 {
				return nil
			}
			if err := xml.Unmarshal(body, out); err != nil {
				return fmt.Errorf("read storage answer: %w", err)
			}
			return nil
		}
		var refusal s3Refusal
		_ = xml.Unmarshal(body, &refusal)
		last = &APIError{Status: resp.StatusCode, Code: refusal.Code, Message: refusal.Message}
		// A store that wants another region says which. Sign again for it,
		// once per region.
		if refusal.Code == "AuthorizationHeaderMalformed" && refusal.Region != "" && refusal.Region != c.region {
			c.region = refusal.Region
			resigned = true
			continue
		}
		if !retryable(resp.StatusCode) || resp.StatusCode == http.StatusNotImplemented {
			return last
		}
	}
	return last
}

// refusedAs reports whether err is the store answering with one of codes.
func refusedAs(err error, codes ...string) bool {
	var refusal *APIError
	if !errors.As(err, &refusal) {
		return false
	}
	for _, code := range codes {
		if refusal.Code == code {
			return true
		}
	}
	return false
}

// unsupported reports a store that does not implement the call at all.
func unsupported(err error) bool {
	var refusal *APIError
	return errors.As(err, &refusal) && (refusal.Status == http.StatusNotImplemented || refusal.Code == "NotImplemented")
}

type s3Buckets struct {
	Owner struct {
		ID string `xml:"ID"`
	} `xml:"Owner"`
	Buckets []struct {
		Name string `xml:"Name"`
	} `xml:"Buckets>Bucket"`
}

func (c *s3) list(ctx context.Context) (*s3Buckets, error) {
	var out s3Buckets
	if err := c.do(ctx, http.MethodGet, "/", nil, &out); err != nil {
		return nil, fmt.Errorf("list buckets: %w", err)
	}
	return &out, nil
}

func (c *s3) Account(ctx context.Context) (string, error) {
	out, err := c.list(ctx)
	if err != nil {
		return "", err
	}
	account := "s3:" + c.base.Host + strings.TrimSuffix(c.base.Path, "/")
	if out.Owner.ID != "" {
		account += "#" + out.Owner.ID
	}
	return account, nil
}

func (c *s3) Buckets(ctx context.Context) ([]Bucket, error) {
	out, err := c.list(ctx)
	if err != nil {
		return nil, err
	}
	buckets := make([]Bucket, 0, len(out.Buckets))
	for _, b := range out.Buckets {
		if b.Name == "" {
			return nil, errors.New("list buckets: a bucket without a name")
		}
		buckets = append(buckets, Bucket{Name: b.Name})
	}
	return buckets, nil
}

// s3Object is one file version, delete marker or plain object.
type s3Object struct {
	Key          string    `xml:"Key"`
	VersionID    string    `xml:"VersionId"`
	Size         int64     `xml:"Size"`
	LastModified time.Time `xml:"LastModified"`
}

// objects walks everything a bucket holds: every version and delete marker
// where the store keeps versions, every object where it does not.
func (c *s3) objects(ctx context.Context, bucket string, each func([]s3Object) error) error {
	if bucket == "" || strings.Contains(bucket, "/") {
		return errors.New("not a bucket name")
	}
	if !c.plain {
		q := url.Values{"versions": {""}, "max-keys": {"1000"}}
		for {
			var out struct {
				IsTruncated         bool       `xml:"IsTruncated"`
				NextKeyMarker       string     `xml:"NextKeyMarker"`
				NextVersionIDMarker string     `xml:"NextVersionIdMarker"`
				Versions            []s3Object `xml:"Version"`
				DeleteMarkers       []s3Object `xml:"DeleteMarker"`
			}
			err := c.do(ctx, http.MethodGet, "/"+bucket, q, &out)
			if unsupported(err) {
				c.plain = true
				break
			}
			if err != nil {
				return fmt.Errorf("list file versions: %w", err)
			}
			if err := each(append(out.Versions, out.DeleteMarkers...)); err != nil {
				return err
			}
			if !out.IsTruncated {
				return nil
			}
			if out.NextKeyMarker == "" {
				return errors.New("list file versions: a truncated page without a marker")
			}
			q.Set("key-marker", out.NextKeyMarker)
			q.Del("version-id-marker")
			if out.NextVersionIDMarker != "" {
				q.Set("version-id-marker", out.NextVersionIDMarker)
			}
		}
	}
	q := url.Values{"list-type": {"2"}, "max-keys": {"1000"}}
	for {
		var out struct {
			IsTruncated bool       `xml:"IsTruncated"`
			Next        string     `xml:"NextContinuationToken"`
			Contents    []s3Object `xml:"Contents"`
		}
		if err := c.do(ctx, http.MethodGet, "/"+bucket, q, &out); err != nil {
			return fmt.Errorf("list files: %w", err)
		}
		if err := each(out.Contents); err != nil {
			return err
		}
		if !out.IsTruncated {
			return nil
		}
		if out.Next == "" {
			return errors.New("list files: a truncated page without a token")
		}
		q.Set("continuation-token", out.Next)
	}
}

func (c *s3) Usage(ctx context.Context, b Bucket) (Usage, error) {
	var u Usage
	err := c.objects(ctx, b.Name, func(objects []s3Object) error {
		for _, o := range objects {
			u.Files++
			u.Bytes += o.Size
			if o.LastModified.After(u.LastWrite) {
				u.LastWrite = o.LastModified.UTC()
			}
		}
		return nil
	})
	return u, err
}

type s3Upload struct {
	Key       string    `xml:"Key"`
	UploadID  string    `xml:"UploadId"`
	Initiated time.Time `xml:"Initiated"`
}

// uploads lists a bucket's unfinished multipart uploads. Their parts are
// billed and keep the bucket from being deleted.
func (c *s3) uploads(ctx context.Context, bucket string) ([]s3Upload, error) {
	var all []s3Upload
	q := url.Values{"uploads": {""}, "max-uploads": {"1000"}}
	for {
		var out struct {
			IsTruncated        bool       `xml:"IsTruncated"`
			NextKeyMarker      string     `xml:"NextKeyMarker"`
			NextUploadIDMarker string     `xml:"NextUploadIdMarker"`
			Uploads            []s3Upload `xml:"Upload"`
		}
		err := c.do(ctx, http.MethodGet, "/"+bucket, q, &out)
		if unsupported(err) {
			return nil, nil
		}
		if err != nil {
			return nil, fmt.Errorf("list unfinished uploads: %w", err)
		}
		all = append(all, out.Uploads...)
		if !out.IsTruncated {
			return all, nil
		}
		if out.NextKeyMarker == "" {
			return nil, errors.New("list unfinished uploads: a truncated page without a marker")
		}
		q.Set("key-marker", out.NextKeyMarker)
		q.Set("upload-id-marker", out.NextUploadIDMarker)
	}
}

func (c *s3) DeleteBucket(ctx context.Context, b Bucket, notWrittenSince time.Time) (Deleted, error) {
	var d Deleted
	written := func(key string, at time.Time) error {
		if !notWrittenSince.IsZero() && at.After(notWrittenSince) {
			return fmt.Errorf("%w: %s on %s", ErrWrittenSince, key, at.UTC().Format(time.RFC3339))
		}
		return nil
	}
	pending, err := c.uploads(ctx, b.Name)
	if err != nil {
		return d, err
	}
	for _, u := range pending {
		if err := written(u.Key, u.Initiated); err != nil {
			return d, err
		}
	}
	// Read the whole bucket before deleting any of it, so a bucket someone
	// still writes to loses nothing. The pages are checked again below for
	// a write that arrives while the deletion runs.
	if err := c.objects(ctx, b.Name, func(objects []s3Object) error {
		for _, o := range objects {
			if err := written(o.Key, o.LastModified); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return d, err
	}
	err = c.objects(ctx, b.Name, func(objects []s3Object) error {
		// The whole page is checked before any of it is deleted.
		for _, o := range objects {
			if err := written(o.Key, o.LastModified); err != nil {
				return err
			}
		}
		for _, o := range objects {
			var q url.Values
			if o.VersionID != "" {
				q = url.Values{"versionId": {o.VersionID}}
			}
			err := c.do(ctx, http.MethodDelete, "/"+b.Name+"/"+o.Key, q, nil)
			if err != nil && !refusedAs(err, "NoSuchKey", "NoSuchVersion") {
				return fmt.Errorf("delete %s: %w", o.Key, err)
			}
			d.Files++
			d.Bytes += o.Size
		}
		return nil
	})
	if err != nil {
		return d, err
	}
	for _, u := range pending {
		err := c.do(ctx, http.MethodDelete, "/"+b.Name+"/"+u.Key, url.Values{"uploadId": {u.UploadID}}, nil)
		if err != nil && !refusedAs(err, "NoSuchUpload") {
			return d, fmt.Errorf("cancel unfinished upload %s: %w", u.Key, err)
		}
	}
	if err := c.do(ctx, http.MethodDelete, "/"+b.Name, nil, nil); err != nil {
		return d, fmt.Errorf("delete bucket: %w", err)
	}
	d.Bucket = true
	return d, nil
}
