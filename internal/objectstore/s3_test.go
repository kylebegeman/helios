package objectstore

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// The two bodyless examples Amazon publishes for Signature Version 4 on S3
// ("Signature Calculations for the Authorization Header"), which pin the
// signing down without a real account.
func TestSignMatchesAmazonsPublishedExamples(t *testing.T) {
	at := time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)
	const keyID, key = "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	for _, tc := range []struct{ name, query, signature string }{
		{"bucket lifecycle", "lifecycle=", "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543"},
		{"list objects", "max-keys=2&prefix=J", "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"},
	} {
		got := sign(keyID, key, "us-east-1", "GET", "examplebucket.s3.amazonaws.com", "/", tc.query, at)
		want := "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=" + tc.signature
		if got != want {
			t.Errorf("%s:\n got %s\nwant %s", tc.name, got, want)
		}
	}
}

func TestEscapeAndRegion(t *testing.T) {
	if got := escape("data/a b+c/é~", true); got != "data/a%20b%2Bc/%C3%A9~" {
		t.Fatalf("path: %s", got)
	}
	if got := escape("a/b", false); got != "a%2Fb" {
		t.Fatalf("query value: %s", got)
	}
	for host, want := range map[string]string{
		"s3.us-west-004.backblazeb2.com": "us-west-004",
		"s3.eu-central-1.amazonaws.com":  "eu-central-1",
		"abc.r2.cloudflarestorage.com":   "auto",
		"minio.internal":                 "us-east-1",
	} {
		if got := regionOf(host); got != want {
			t.Errorf("%s: region %s, want %s", host, got, want)
		}
	}
}

type fakeObject struct {
	key, version string
	size         int64
	at           time.Time
	marker       bool
}

// fakeS3 is a path-style S3 server over a map, checking every signature
// with the signer under test's own key.
type fakeS3 struct {
	t        *testing.T
	mu       sync.Mutex
	buckets  map[string][]fakeObject
	uploads  map[string][]s3Upload
	region   string
	versions bool
	page     int
	deletes  []string
	busy     int
	// noCancel refuses to cancel an unfinished upload.
	noCancel bool
	// sticky answers a deletion with success and keeps the file.
	sticky bool
	// resumed counts listings that carried on from a marker after
	// something was deleted.
	resumed int
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	at, err := time.Parse("20060102T150405Z", r.Header.Get("x-amz-date"))
	if err != nil {
		http.Error(w, "date", http.StatusForbidden)
		return
	}
	if !strings.Contains(r.Header.Get("Authorization"), "/"+f.region+"/s3/aws4_request") {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `<Error><Code>AuthorizationHeaderMalformed</Code><Message>wrong region</Message><Region>%s</Region></Error>`, f.region)
		return
	}
	want := sign("id", "secret", f.region, r.Method, r.Host, r.URL.EscapedPath(), canonicalQuery(r.URL.Query()), at)
	if r.Header.Get("Authorization") != want {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `<Error><Code>SignatureDoesNotMatch</Code><Message>bad signature</Message></Error>`)
		return
	}
	if f.busy > 0 {
		f.busy--
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, `<Error><Code>SlowDown</Code><Message>busy</Message></Error>`)
		return
	}
	bucket, key, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	q := r.URL.Query()
	switch {
	case bucket == "" && r.Method == http.MethodGet:
		names := make([]string, 0, len(f.buckets))
		for name := range f.buckets {
			names = append(names, name)
		}
		sort.Strings(names)
		fmt.Fprint(w, `<ListAllMyBucketsResult><Owner><ID>owner-1</ID></Owner><Buckets>`)
		for _, name := range names {
			fmt.Fprintf(w, `<Bucket><Name>%s</Name></Bucket>`, name)
		}
		fmt.Fprint(w, `</Buckets></ListAllMyBucketsResult>`)
	case key == "" && r.Method == http.MethodGet && q.Has("uploads"):
		fmt.Fprint(w, `<ListMultipartUploadsResult><IsTruncated>false</IsTruncated>`)
		for _, u := range f.uploads[bucket] {
			fmt.Fprintf(w, `<Upload><Key>%s</Key><UploadId>%s</UploadId><Initiated>%s</Initiated></Upload>`, u.Key, u.UploadID, u.Initiated.Format(time.RFC3339))
		}
		fmt.Fprint(w, `</ListMultipartUploadsResult>`)
	case key == "" && r.Method == http.MethodGet && q.Has("versions"):
		if !f.versions {
			w.WriteHeader(http.StatusNotImplemented)
			fmt.Fprint(w, `<Error><Code>NotImplemented</Code><Message>no versions here</Message></Error>`)
			return
		}
		if q.Get("key-marker") != "" && len(f.deletes) > 0 {
			f.resumed++
		}
		f.listPage(w, bucket, q.Get("key-marker"), true)
	case key == "" && r.Method == http.MethodGet && q.Get("list-type") == "2":
		f.listPage(w, bucket, q.Get("continuation-token"), false)
	case key == "" && r.Method == http.MethodDelete:
		if len(f.buckets[bucket]) > 0 || len(f.uploads[bucket]) > 0 {
			w.WriteHeader(http.StatusConflict)
			fmt.Fprint(w, `<Error><Code>BucketNotEmpty</Code><Message>not empty</Message></Error>`)
			return
		}
		delete(f.buckets, bucket)
		f.deletes = append(f.deletes, "bucket "+bucket)
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodDelete && q.Has("uploadId") && f.noCancel:
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `<Error><Code>AccessDenied</Code><Message>not allowed</Message></Error>`)
	case r.Method == http.MethodDelete && q.Has("uploadId"):
		var rest []s3Upload
		for _, u := range f.uploads[bucket] {
			if u.UploadID != q.Get("uploadId") {
				rest = append(rest, u)
			}
		}
		f.uploads[bucket] = rest
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodDelete:
		var rest []fakeObject
		for _, o := range f.buckets[bucket] {
			if o.key == key && o.version == q.Get("versionId") && !f.sticky {
				f.deletes = append(f.deletes, bucket+"/"+key+"@"+o.version)
				continue
			}
			rest = append(rest, o)
		}
		f.buckets[bucket] = rest
		w.WriteHeader(http.StatusNoContent)
	default:
		f.t.Errorf("unexpected request %s %s", r.Method, r.URL)
		w.WriteHeader(http.StatusBadRequest)
	}
}

// listPage serves a page of at most f.page entries after marker, in key
// order. The marker is the last key of the page before.
func (f *fakeS3) listPage(w http.ResponseWriter, bucket, marker string, versions bool) {
	objects, ok := f.buckets[bucket]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `<Error><Code>NoSuchBucket</Code><Message>no bucket</Message></Error>`)
		return
	}
	sorted := append([]fakeObject{}, objects...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].key < sorted[j].key })
	var page []fakeObject
	truncated := false
	for _, o := range sorted {
		if marker != "" && o.key <= marker {
			continue
		}
		if len(page) == f.page {
			truncated = true
			break
		}
		page = append(page, o)
	}
	last := ""
	if len(page) > 0 {
		last = page[len(page)-1].key
	}
	if versions {
		fmt.Fprintf(w, `<ListVersionsResult><IsTruncated>%t</IsTruncated><NextKeyMarker>%s</NextKeyMarker>`, truncated, last)
		for _, o := range page {
			tag := "Version"
			if o.marker {
				tag = "DeleteMarker"
			}
			fmt.Fprintf(w, `<%s><Key>%s</Key><VersionId>%s</VersionId><Size>%d</Size><LastModified>%s</LastModified></%s>`, tag, o.key, o.version, o.size, o.at.Format(time.RFC3339), tag)
		}
		fmt.Fprint(w, `</ListVersionsResult>`)
		return
	}
	fmt.Fprintf(w, `<ListBucketResult><IsTruncated>%t</IsTruncated><NextContinuationToken>%s</NextContinuationToken>`, truncated, last)
	for _, o := range page {
		fmt.Fprintf(w, `<Contents><Key>%s</Key><Size>%d</Size><LastModified>%s</LastModified></Contents>`, o.key, o.size, o.at.Format(time.RFC3339))
	}
	fmt.Fprint(w, `</ListBucketResult>`)
}

var removedAt = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func s3Fixture(t *testing.T) (*fakeS3, Store) {
	t.Helper()
	old := removedAt.Add(-24 * time.Hour)
	fake := &fakeS3{t: t, region: "us-east-1", versions: true, page: 2, buckets: map[string][]fakeObject{
		// Unique keys, so a page boundary never splits one key's versions:
		// the fake pages by key alone.
		"helios-site": {
			{key: "config", version: "v1", size: 100, at: old},
			{key: "data/aa/pack one", version: "v2", size: 4000, at: old},
			{key: "data/bb/pack2", version: "v3", size: 500, at: old.Add(time.Hour)},
			{key: "index/1", version: "v4", size: 0, at: old, marker: true},
			{key: "snapshots/1", version: "v5", size: 50, at: old},
		},
		"helios-other": {{key: "config", version: "v1", size: 7, at: removedAt.Add(time.Hour)}},
	}, uploads: map[string][]s3Upload{}}
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)
	store, err := New(Config{Kind: "s3", Endpoint: server.URL + "/", KeyID: "id", Key: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	store.(*s3).wait = func(context.Context, int) error { return nil }
	return fake, store
}

func TestS3ListsBucketsAndAddsUpEveryVersion(t *testing.T) {
	ctx := context.Background()
	fake, store := s3Fixture(t)
	fake.busy = 2 // the first answers say "busy"; the request is retried
	account, err := store.Account(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(account, "s3:127.0.0.1:") || !strings.HasSuffix(account, "#owner-1") {
		t.Fatalf("account %q", account)
	}
	buckets, err := store.Buckets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(buckets) != 2 || buckets[0].Name != "helios-other" || buckets[1].Name != "helios-site" {
		t.Fatalf("buckets: %v", buckets)
	}
	usage, err := store.Usage(ctx, Bucket{Name: "helios-site"})
	if err != nil {
		t.Fatal(err)
	}
	if usage.Bytes != 4650 || usage.Files != 5 || !usage.LastWrite.Equal(removedAt.Add(-23*time.Hour)) {
		t.Fatalf("usage: %+v", usage)
	}
	if _, err := store.Usage(ctx, Bucket{Name: "helios-gone"}); err == nil {
		t.Fatal("usage of a missing bucket succeeded")
	}
}

func TestS3SignsAgainForTheRegionTheStoreNames(t *testing.T) {
	fake, store := s3Fixture(t)
	fake.region = "eu-central-003"
	if _, err := store.Buckets(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := store.(*s3).region; got != "eu-central-003" {
		t.Fatalf("region stayed %s", got)
	}
}

func TestS3DeletesEveryVersionThenTheBucket(t *testing.T) {
	ctx := context.Background()
	fake, store := s3Fixture(t)
	fake.uploads["helios-site"] = []s3Upload{{Key: "data/cc/half", UploadID: "u1", Initiated: removedAt.Add(-time.Hour)}}
	deleted, err := store.DeleteBucket(ctx, Bucket{Name: "helios-site"}, Check{NotWrittenSince: removedAt})
	if err != nil {
		t.Fatal(err)
	}
	if !deleted.Bucket || deleted.Files != 5 || deleted.Bytes != 4650 {
		t.Fatalf("deleted: %+v", deleted)
	}
	if _, there := fake.buckets["helios-site"]; there {
		t.Fatal("the bucket is still there")
	}
	if len(fake.buckets["helios-other"]) != 1 {
		t.Fatal("another bucket lost files")
	}
	want := []string{"helios-site/config@v1", "helios-site/data/aa/pack one@v2", "helios-site/data/bb/pack2@v3", "helios-site/index/1@v4", "helios-site/snapshots/1@v5", "bucket helios-site"}
	if strings.Join(fake.deletes, "|") != strings.Join(want, "|") {
		t.Fatalf("deletes: %v", fake.deletes)
	}
}

func TestS3DeletesNothingFromABucketWrittenSince(t *testing.T) {
	ctx := context.Background()
	fake, store := s3Fixture(t)
	// The newest write sorts last, on a later page than the first files.
	fake.buckets["helios-site"] = append(fake.buckets["helios-site"], fakeObject{key: "snapshots/2", version: "v9", size: 1, at: removedAt.Add(time.Minute)})
	deleted, err := store.DeleteBucket(ctx, Bucket{Name: "helios-site"}, Check{NotWrittenSince: removedAt})
	if !errors.Is(err, ErrWrittenSince) {
		t.Fatalf("error: %v", err)
	}
	if deleted.Files != 0 || deleted.Bucket || len(fake.deletes) != 0 || len(fake.buckets["helios-site"]) != 6 {
		t.Fatalf("something was deleted: %+v %v", deleted, fake.deletes)
	}

	// An unfinished upload started since counts as a write too.
	fake.buckets["helios-site"] = fake.buckets["helios-site"][:5]
	fake.uploads["helios-site"] = []s3Upload{{Key: "data/dd/new", UploadID: "u2", Initiated: removedAt.Add(time.Hour)}}
	if _, err := store.DeleteBucket(ctx, Bucket{Name: "helios-site"}, Check{NotWrittenSince: removedAt}); !errors.Is(err, ErrWrittenSince) || len(fake.deletes) != 0 {
		t.Fatalf("unfinished upload: %v %v", err, fake.deletes)
	}
}

func TestS3WithoutVersionsDeletesItsObjects(t *testing.T) {
	ctx := context.Background()
	fake, store := s3Fixture(t)
	fake.versions = false
	for i := range fake.buckets["helios-site"] {
		fake.buckets["helios-site"][i].version = ""
		fake.buckets["helios-site"][i].marker = false
	}
	usage, err := store.Usage(ctx, Bucket{Name: "helios-site"})
	if err != nil || usage.Files != 5 {
		t.Fatalf("usage: %+v %v", usage, err)
	}
	deleted, err := store.DeleteBucket(ctx, Bucket{Name: "helios-site"}, Check{NotWrittenSince: removedAt})
	if err != nil || !deleted.Bucket || deleted.Files != 5 {
		t.Fatalf("deleted: %+v %v", deleted, err)
	}
}

func TestS3RefusalIsReportedAndDeletesNothing(t *testing.T) {
	ctx := context.Background()
	fake, _ := s3Fixture(t)
	server := httptest.NewServer(fake)
	defer server.Close()
	wrong, err := New(Config{Kind: "s3", Endpoint: server.URL, KeyID: "id", Key: "not the secret"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = wrong.DeleteBucket(ctx, Bucket{Name: "helios-site"}, Check{NotWrittenSince: removedAt})
	var refusal *APIError
	if !errors.As(err, &refusal) || refusal.Code != "SignatureDoesNotMatch" || len(fake.deletes) != 0 {
		t.Fatalf("error %v, deletes %v", err, fake.deletes)
	}
	if _, err := New(Config{Kind: "s3", Endpoint: "ftp://x", KeyID: "id", Key: "k"}); err == nil {
		t.Fatal("an ftp endpoint was accepted")
	}
	if _, err := New(Config{Kind: "s3", Endpoint: server.URL}); err == nil {
		t.Fatal("missing credentials were accepted")
	}
}

// A check on the bucket's contents refuses before anything is deleted,
// whether it objects to one name or to the bucket as a whole, and is asked
// again about each page as it goes.
func TestS3DeletesNothingFromABucketItsCheckRefuses(t *testing.T) {
	ctx := context.Background()
	refusal := errors.New("not ours")
	for name, check := range map[string]Check{
		"a name": {Key: func(key string) error {
			if strings.HasPrefix(key, "data/") {
				return refusal
			}
			return nil
		}},
		"the whole": {Whole: func() error { return refusal }},
	} {
		fake, store := s3Fixture(t)
		for _, try := range []func() error{
			func() error { return store.Examine(ctx, Bucket{Name: "helios-site"}, check) },
			func() error { _, err := store.DeleteBucket(ctx, Bucket{Name: "helios-site"}, check); return err },
		} {
			if err := try(); !errors.Is(err, refusal) {
				t.Fatalf("%s: error %v", name, err)
			}
			if len(fake.deletes) != 0 || len(fake.buckets["helios-site"]) != 5 {
				t.Fatalf("%s: something was deleted: %v", name, fake.deletes)
			}
		}
	}

	// What passes is read whole, judged once, and then every name is asked
	// about a second time on its way out.
	fake, store := s3Fixture(t)
	seen, judged := map[string]int{}, 0
	check := Check{Key: func(key string) error { seen[key]++; return nil }, Whole: func() error {
		judged++
		if len(fake.deletes) != 0 {
			t.Fatal("judged after the deletion began")
		}
		return nil
	}}
	if err := store.Examine(ctx, Bucket{Name: "helios-site"}, check); err != nil || len(fake.deletes) != 0 || judged != 1 {
		t.Fatalf("examine: %v, deletes %v, judged %d", err, fake.deletes, judged)
	}
	if _, err := store.DeleteBucket(ctx, Bucket{Name: "helios-site"}, check); err != nil || judged != 2 {
		t.Fatalf("delete: %v, judged %d", err, judged)
	}
	if seen["config"] != 3 {
		t.Fatalf("config was asked about %d times, want once to examine, once to read and once to delete: %v", seen["config"], seen)
	}
}

// What a deletion that stops leaves behind must be the end of the order of
// names, where a repository keeps its snapshots: that is what lets the next
// attempt tell whose bucket it is. A page lists delete markers after its
// versions, and unfinished uploads are listed apart.
func TestS3DeletesInTheOrderOfNamesAndCancelsUploadsFirst(t *testing.T) {
	ctx := context.Background()
	fake, store := s3Fixture(t)
	fake.page = 10 // one page: four versions, then the marker for index/1
	if _, err := store.DeleteBucket(ctx, Bucket{Name: "helios-site"}, Check{NotWrittenSince: removedAt}); err != nil {
		t.Fatal(err)
	}
	want := []string{"helios-site/config@v1", "helios-site/data/aa/pack one@v2", "helios-site/data/bb/pack2@v3", "helios-site/index/1@v4", "helios-site/snapshots/1@v5", "bucket helios-site"}
	if strings.Join(fake.deletes, "\n") != strings.Join(want, "\n") {
		t.Fatalf("deleted in this order:\n%s", strings.Join(fake.deletes, "\n"))
	}

	// An upload that cannot be cancelled stops the deletion before any file
	// is gone, so the bucket is still whole for the next attempt.
	fake, store = s3Fixture(t)
	fake.noCancel = true
	fake.uploads["helios-site"] = []s3Upload{{Key: "data/cc/half", UploadID: "u1", Initiated: removedAt.Add(-time.Hour)}}
	if _, err := store.DeleteBucket(ctx, Bucket{Name: "helios-site"}, Check{NotWrittenSince: removedAt}); err == nil || !strings.Contains(err.Error(), "cancel unfinished upload") {
		t.Fatalf("error %v", err)
	}
	if len(fake.deletes) != 0 || len(fake.buckets["helios-site"]) != 5 {
		t.Fatalf("files were deleted before the unfinished upload was cancelled: %v", fake.deletes)
	}
}

// A listing is never carried on past a page that was just deleted: its
// marker would name a file version that is gone. And a store that goes on
// listing what it said it deleted ends the deletion, not the night.
func TestS3ListsFromTheStartAfterEachDeletedPage(t *testing.T) {
	ctx := context.Background()
	fake, store := s3Fixture(t) // pages of two
	if _, err := store.DeleteBucket(ctx, Bucket{Name: "helios-site"}, Check{NotWrittenSince: removedAt}); err != nil {
		t.Fatal(err)
	}
	if fake.resumed != 0 || len(fake.deletes) != 6 {
		t.Fatalf("%d listing(s) carried on from a marker after a deletion; deleted %v", fake.resumed, fake.deletes)
	}

	fake, store = s3Fixture(t)
	fake.sticky = true
	if _, err := store.DeleteBucket(ctx, Bucket{Name: "helios-site"}, Check{NotWrittenSince: removedAt}); err == nil || !strings.Contains(err.Error(), "still lists it after deleting it") {
		t.Fatalf("error %v", err)
	}
}
