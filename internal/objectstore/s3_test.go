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
	// lag is how many listings after a deletion still show what it
	// deleted. behind counts the ones still to come, of gone.
	lag    int
	behind int
	gone   map[string][]fakeObject
	// ignoresVersions answers a listing of versions with the plain listing,
	// as a store does that does not know the question.
	ignoresVersions bool
	// firstPlainOnly knows only the first version of the plain listing: it
	// carries on after a marker and hands out no token. namesNext has it
	// name the marker to carry on after.
	firstPlainOnly bool
	namesNext      bool
	// deaf ignores where a listing is told to carry on, and hollow answers
	// one with pages that hold nothing and say there is more.
	deaf   bool
	hollow bool
	// backwards has the markers of hollow pages of versions go down.
	backwards bool
	// answer, when set, is what any listing of a bucket's files gets.
	answer *string
	// lists counts the listings of a bucket's files.
	lists int
	// uploadPage, when set, answers the nth listing of unfinished uploads,
	// counted from one and given the marker it was asked to carry on after.
	uploadPage  func(n int, marker string) string
	uploadLists int
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
	case key == "" && r.Method == http.MethodGet && q.Has("uploads") && f.uploadPage != nil:
		f.uploadLists++
		fmt.Fprint(w, f.uploadPage(f.uploadLists, q.Get("key-marker")+"@"+q.Get("upload-id-marker")))
	case key == "" && r.Method == http.MethodGet && q.Has("uploads"):
		fmt.Fprint(w, `<ListMultipartUploadsResult><IsTruncated>false</IsTruncated>`)
		for _, u := range f.uploads[bucket] {
			fmt.Fprintf(w, `<Upload><Key>%s</Key><UploadId>%s</UploadId><Initiated>%s</Initiated></Upload>`, u.Key, u.UploadID, u.Initiated.Format(time.RFC3339))
		}
		fmt.Fprint(w, `</ListMultipartUploadsResult>`)
	case key == "" && r.Method == http.MethodGet && f.answer != nil:
		f.lists++
		fmt.Fprint(w, *f.answer)
	case key == "" && r.Method == http.MethodGet && q.Has("versions") && !f.ignoresVersions:
		f.lists++
		if !f.versions {
			w.WriteHeader(http.StatusNotImplemented)
			fmt.Fprint(w, `<Error><Code>NotImplemented</Code><Message>no versions here</Message></Error>`)
			return
		}
		if q.Get("key-marker") != "" && len(f.deletes) > 0 {
			f.resumed++
		}
		marker := q.Get("key-marker")
		if f.deaf {
			marker = ""
		}
		f.listPage(w, bucket, marker, true)
	case key == "" && r.Method == http.MethodGet && (q.Get("list-type") == "2" || q.Has("versions")):
		f.lists++
		// Only a listing asked for in its second version carries on from a
		// token; one that was asked for versions is the first version.
		marker := q.Get("marker")
		if q.Get("list-type") == "2" && !f.firstPlainOnly {
			marker = q.Get("continuation-token")
		}
		if f.deaf {
			marker = ""
		}
		f.listPage(w, bucket, marker, false)
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
		if q.Has("versionId") && (f.ignoresVersions || !f.versions) {
			f.t.Errorf("%s was deleted by a version id in a store without versions", key)
		}
		var rest []fakeObject
		for _, o := range f.buckets[bucket] {
			if o.key == key && o.version == q.Get("versionId") && !f.sticky {
				f.deletes = append(f.deletes, bucket+"/"+key+"@"+o.version)
				if f.lag > 0 {
					if f.gone == nil {
						f.gone = map[string][]fakeObject{}
					}
					f.gone[bucket] = append(f.gone[bucket], o)
					f.behind = f.lag
				}
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
	// A listing that is behind still shows what was deleted.
	if f.behind > 0 {
		f.behind--
		sorted = append(sorted, f.gone[bucket]...)
	} else {
		delete(f.gone, bucket)
	}
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
	if versions && f.hollow {
		// Nothing, more to come, and a marker no page before had.
		n := f.lists
		if f.backwards {
			n = 9999 - n
		}
		fmt.Fprintf(w, `<ListVersionsResult><IsTruncated>true</IsTruncated><NextKeyMarker>k%04d</NextKeyMarker><NextVersionIdMarker>v%d</NextVersionIdMarker></ListVersionsResult>`, n, f.lists)
		return
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
	switch {
	case f.hollow && f.firstPlainOnly:
		// Nothing, more to come, and nothing to say where.
		fmt.Fprint(w, `<ListBucketResult><IsTruncated>true</IsTruncated></ListBucketResult>`)
		return
	case f.hollow:
		// Nothing, more to come, and a token no page before had.
		fmt.Fprintf(w, `<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>t%d</NextContinuationToken></ListBucketResult>`, f.lists)
		return
	case !f.firstPlainOnly:
		fmt.Fprintf(w, `<ListBucketResult><IsTruncated>%t</IsTruncated><NextContinuationToken>%s</NextContinuationToken>`, truncated, last)
	case f.namesNext && truncated:
		fmt.Fprintf(w, `<ListBucketResult><IsTruncated>true</IsTruncated><NextMarker>%s</NextMarker>`, last)
	default:
		fmt.Fprintf(w, `<ListBucketResult><IsTruncated>%t</IsTruncated>`, truncated)
	}
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
	store.(*s3).settle = func(context.Context, time.Duration) error { return nil }
	return fake, store
}

// newClient is another client of a fake store, one that has not asked it
// anything yet.
func newClient(t *testing.T, fake *fakeS3) Store {
	t.Helper()
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)
	store, err := New(Config{Kind: "s3", Endpoint: server.URL + "/", KeyID: "id", Key: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	store.(*s3).wait = func(context.Context, int) error { return nil }
	store.(*s3).settle = func(context.Context, time.Duration) error { return nil }
	return store
}

// plainFixture is the fixture as a store without versions holds it.
func plainFixture(t *testing.T) (*fakeS3, Store) {
	t.Helper()
	fake, store := s3Fixture(t)
	for i := range fake.buckets["helios-site"] {
		fake.buckets["helios-site"][i].version = ""
		fake.buckets["helios-site"][i].marker = false
	}
	return fake, store
}

// settles records the waits a store makes before it lists a bucket again.
func settles(store Store) *[]time.Duration {
	var waits []time.Duration
	store.(*s3).settle = func(_ context.Context, d time.Duration) error {
		waits = append(waits, d)
		return nil
	}
	return &waits
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

// A store's listing may trail its deletions for a moment and start with the
// file that just went. The bucket is listed again, a little later each
// time, and the deletion carries on once the listing has caught up.
func TestS3ListsAgainWhenTheListingIsBehindItsDeletions(t *testing.T) {
	ctx := context.Background()
	fake, store := s3Fixture(t) // pages of two: three pages to delete
	fake.lag = len(relistAfter)
	waits := settles(store)
	deleted, err := store.DeleteBucket(ctx, Bucket{Name: "helios-site"}, Check{NotWrittenSince: removedAt})
	if err != nil {
		t.Fatal(err)
	}
	if !deleted.Bucket || deleted.Files != 5 || deleted.Bytes != 4650 {
		t.Fatalf("deleted: %+v", deleted)
	}
	want := []string{"helios-site/config@v1", "helios-site/data/aa/pack one@v2", "helios-site/data/bb/pack2@v3", "helios-site/index/1@v4", "helios-site/snapshots/1@v5", "bucket helios-site"}
	if strings.Join(fake.deletes, "|") != strings.Join(want, "|") {
		t.Fatalf("deletes: %v", fake.deletes)
	}
	// Every page waited out the whole lag, starting from the shortest wait.
	var all []time.Duration
	for range 3 {
		all = append(all, relistAfter...)
	}
	if fmt.Sprint(*waits) != fmt.Sprint(all) {
		t.Fatalf("waited %v, want %v", *waits, all)
	}
	if fake.resumed != 0 {
		t.Fatalf("%d listing(s) carried on from a marker after a deletion", fake.resumed)
	}
}

// The listings are bounded. A store still behind after the last of them
// ends the deletion with what it has done so far, and the next attempt
// carries on from there.
func TestS3GivesUpOnAListingThatStaysBehindItsDeletions(t *testing.T) {
	ctx := context.Background()
	fake, store := s3Fixture(t)
	fake.lag = len(relistAfter) + 1
	waits := settles(store)
	deleted, err := store.DeleteBucket(ctx, Bucket{Name: "helios-site"}, Check{NotWrittenSince: removedAt})
	if err == nil || !strings.Contains(err.Error(), "delete config: the store still lists it after deleting it") {
		t.Fatalf("error %v", err)
	}
	if deleted.Bucket || deleted.Files != 2 || len(fake.deletes) != 2 {
		t.Fatalf("deleted %+v: %v", deleted, fake.deletes)
	}
	if fmt.Sprint(*waits) != fmt.Sprint(relistAfter) {
		t.Fatalf("waited %v, want %v", *waits, relistAfter)
	}

	// A wait that is cut short ends the deletion there, with no listing
	// after it.
	fake, store = s3Fixture(t)
	fake.lag = 1
	stopped := errors.New("stopped")
	store.(*s3).settle = func(context.Context, time.Duration) error { return stopped }
	if _, err := store.DeleteBucket(ctx, Bucket{Name: "helios-site"}, Check{NotWrittenSince: removedAt}); !errors.Is(err, stopped) {
		t.Fatalf("error %v", err)
	}
	// Three listings to read the bucket whole, one to delete the first
	// page, and the one that was behind.
	if fake.lists != 5 || len(fake.deletes) != 2 {
		t.Fatalf("%d listing(s), deleted %v", fake.lists, fake.deletes)
	}
}

// The wait before a bucket is listed again ends when its context does.
func TestS3WaitToListAgainEndsWithItsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() { done <- pause(ctx, time.Hour) }()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the wait outlived its context")
	}
	if err := pause(context.Background(), time.Millisecond); err != nil {
		t.Fatal(err)
	}
	store, err := New(Config{Kind: "s3", Endpoint: "https://s3.example.com", KeyID: "id", Key: "secret"})
	if err != nil || store.(*s3).settle == nil {
		t.Fatalf("a new store has no wait to list again with: %v", err)
	}
}

// A store that does not know a listing of versions may answer it with the
// plain listing instead of refusing. Read as versions that answer holds
// none, and the bucket would pass for empty. It is told by its root element
// and the bucket is read through the plain listing.
func TestS3ThatAnswersAVersionListingWithAPlainOneIsReadThroughThePlainListing(t *testing.T) {
	ctx := context.Background()
	for _, page := range []int{2, 10} { // a truncated first answer, and a whole one
		fake, store := plainFixture(t)
		fake.ignoresVersions, fake.page = true, page
		usage, err := store.Usage(ctx, Bucket{Name: "helios-site"})
		if err != nil || usage.Files != 5 || usage.Bytes != 4650 {
			t.Fatalf("pages of %d: usage %+v %v", page, usage, err)
		}

		// Examine reads what the deletion would: every name, once. It is
		// asked of a client that finds out about the store for itself.
		store = newClient(t, fake)
		seen := map[string]int{}
		if err := store.Examine(ctx, Bucket{Name: "helios-site"}, Check{Key: func(key string) error { seen[key]++; return nil }}); err != nil {
			t.Fatalf("pages of %d: examine %v", page, err)
		}
		if len(seen) != 5 || seen["config"] != 1 || seen["snapshots/1"] != 1 {
			t.Fatalf("pages of %d: examined %v", page, seen)
		}

		// A check that refuses a name still keeps everything.
		refusal := errors.New("not ours")
		_, err = store.DeleteBucket(ctx, Bucket{Name: "helios-site"}, Check{Key: func(key string) error {
			if strings.HasPrefix(key, "snapshots/") {
				return refusal
			}
			return nil
		}})
		if !errors.Is(err, refusal) || len(fake.deletes) != 0 {
			t.Fatalf("pages of %d: error %v, deletes %v", page, err, fake.deletes)
		}

		// The deletion goes in the order of the names, by name alone.
		fake.uploads["helios-site"] = []s3Upload{{Key: "data/cc/half", UploadID: "u1", Initiated: removedAt.Add(-time.Hour)}}
		deleted, err := store.DeleteBucket(ctx, Bucket{Name: "helios-site"}, Check{NotWrittenSince: removedAt})
		if err != nil || !deleted.Bucket || deleted.Files != 5 || deleted.Bytes != 4650 {
			t.Fatalf("pages of %d: deleted %+v %v", page, deleted, err)
		}
		want := []string{"helios-site/config@", "helios-site/data/aa/pack one@", "helios-site/data/bb/pack2@", "helios-site/index/1@", "helios-site/snapshots/1@", "bucket helios-site"}
		if strings.Join(fake.deletes, "|") != strings.Join(want, "|") {
			t.Fatalf("pages of %d: deletes %v", page, fake.deletes)
		}
	}
}

// Such a store may know only the first version of the plain listing, which
// hands out no token: it carries on after the marker the store names, or
// after the last name of the page.
func TestS3ThatKnowsOnlyTheFirstPlainListingIsReadToItsEnd(t *testing.T) {
	ctx := context.Background()
	for _, namesNext := range []bool{false, true} {
		fake, store := plainFixture(t)
		fake.ignoresVersions, fake.firstPlainOnly, fake.namesNext = true, true, namesNext
		usage, err := store.Usage(ctx, Bucket{Name: "helios-site"})
		if err != nil || usage.Files != 5 || usage.Bytes != 4650 {
			t.Fatalf("names the next marker %t: usage %+v %v", namesNext, usage, err)
		}
		deleted, err := store.DeleteBucket(ctx, Bucket{Name: "helios-site"}, Check{NotWrittenSince: removedAt})
		if err != nil || !deleted.Bucket || deleted.Files != 5 {
			t.Fatalf("names the next marker %t: deleted %+v %v", namesNext, deleted, err)
		}
	}
}

// A plain listing that says there is more and does not carry on ends in an
// error. It is never read round and round, and nothing is deleted by it.
func TestS3PlainListingThatDoesNotCarryOnEndsInAnError(t *testing.T) {
	for name, broken := range map[string]struct {
		set  func(*fakeS3)
		want string
	}{
		"the same page again":            {func(f *fakeS3) { f.deaf = true }, "the store gave a page it had already given"},
		"the same page, first version":   {func(f *fakeS3) { f.deaf, f.firstPlainOnly = true, true }, "the store gave a page it had already given"},
		"pages of nothing":               {func(f *fakeS3) { f.hollow = true }, "pages in a row held nothing and said there was more"},
		"nothing, and nowhere to resume": {func(f *fakeS3) { f.hollow, f.firstPlainOnly = true, true }, "a truncated page without a token or a name to carry on after"},
	} {
		// A listing that goes round is stopped by the clock, and fails here.
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		fake, store := plainFixture(t)
		fake.versions = false
		broken.set(fake)
		_, err := store.Usage(ctx, Bucket{Name: "helios-site"})
		if err == nil || !strings.Contains(err.Error(), broken.want) {
			t.Fatalf("%s: usage error %v", name, err)
		}
		_, err = store.DeleteBucket(ctx, Bucket{Name: "helios-site"}, Check{NotWrittenSince: removedAt})
		if err == nil || !strings.Contains(err.Error(), broken.want) || len(fake.deletes) != 0 {
			t.Fatalf("%s: delete error %v, deletes %v", name, err, fake.deletes)
		}
		if fake.lists > 4*s3EmptyPages {
			t.Fatalf("%s: the bucket was listed %d times", name, fake.lists)
		}
		cancel()
	}
}

// A listing of versions is held to the same: one that says there is more and
// names a marker it has already passed, or goes on with pages that hold
// nothing, ends in an error and deletes nothing.
func TestS3VersionListingThatDoesNotCarryOnEndsInAnError(t *testing.T) {
	for name, broken := range map[string]struct {
		set  func(*fakeS3)
		want string
	}{
		"the same marker again": {func(f *fakeS3) { f.deaf = true }, "the store named a marker it had already passed"},
		"a marker further back": {func(f *fakeS3) { f.hollow, f.backwards = true, true }, "the store named a marker it had already passed"},
		"pages of nothing":      {func(f *fakeS3) { f.hollow = true }, "pages in a row held nothing and said there was more"},
	} {
		// A listing that goes round is stopped by the clock, and fails here.
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		fake, store := s3Fixture(t)
		broken.set(fake)
		_, err := store.Usage(ctx, Bucket{Name: "helios-site"})
		if err == nil || !strings.Contains(err.Error(), broken.want) {
			t.Fatalf("%s: usage error %v", name, err)
		}
		_, err = store.DeleteBucket(ctx, Bucket{Name: "helios-site"}, Check{NotWrittenSince: removedAt})
		if err == nil || !strings.Contains(err.Error(), broken.want) || len(fake.deletes) != 0 {
			t.Fatalf("%s: delete error %v, deletes %v", name, err, fake.deletes)
		}
		if fake.lists > 4*s3EmptyPages {
			t.Fatalf("%s: the bucket was listed %d times", name, fake.lists)
		}
		cancel()
	}
}

// The listing of unfinished uploads is held to the same as the listings of
// files: it is read to its end across pages, a store without it may answer
// with the plain listing of the bucket, and one that does not carry on ends
// in an error.
func TestS3ListsUnfinishedUploadsToTheEndOrEndsInAnError(t *testing.T) {
	upload := func(key, id string) string {
		return fmt.Sprintf(`<Upload><Key>%s</Key><UploadId>%s</UploadId><Initiated>%s</Initiated></Upload>`, key, id, removedAt.Add(-time.Hour).Format(time.RFC3339))
	}
	more := func(key, id, uploads string) string {
		return fmt.Sprintf(`<ListMultipartUploadsResult><IsTruncated>true</IsTruncated><NextKeyMarker>%s</NextKeyMarker><NextUploadIdMarker>%s</NextUploadIdMarker>%s</ListMultipartUploadsResult>`, key, id, uploads)
	}
	const last = `<ListMultipartUploadsResult><IsTruncated>false</IsTruncated></ListMultipartUploadsResult>`
	const plain = `<ListBucketResult><IsTruncated>true</IsTruncated><Contents><Key>config</Key></Contents></ListBucketResult>`

	// Two uploads of one name and one of another, a page each. All three
	// are found and cancelled, and the bucket goes.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	fake, store := s3Fixture(t)
	fake.uploads["helios-site"] = []s3Upload{{Key: "data/cc/half", UploadID: "u1"}, {Key: "data/cc/half", UploadID: "u2"}, {Key: "data/dd/half", UploadID: "u3"}}
	var asked []string
	fake.uploadPage = func(_ int, marker string) string {
		asked = append(asked, marker)
		switch marker {
		case "@":
			return more("data/cc/half", "u1", upload("data/cc/half", "u1"))
		case "data/cc/half@u1":
			return more("data/cc/half", "u2", upload("data/cc/half", "u2"))
		case "data/cc/half@u2":
			return more("data/dd/half", "u3", upload("data/dd/half", "u3"))
		}
		return last
	}
	pending, err := store.(*s3).uploads(ctx, "helios-site")
	if err != nil || len(pending) != 3 {
		t.Fatalf("uploads %v, error %v", pending, err)
	}
	if strings.Join(asked, " ") != "@ data/cc/half@u1 data/cc/half@u2 data/dd/half@u3" {
		t.Fatalf("asked %v", asked)
	}
	if deleted, err := store.DeleteBucket(ctx, Bucket{Name: "helios-site"}, Check{NotWrittenSince: removedAt}); err != nil || !deleted.Bucket || len(fake.uploads["helios-site"]) != 0 {
		t.Fatalf("deleted %+v, error %v, uploads left %v", deleted, err, fake.uploads["helios-site"])
	}

	// A store that answers the question with the plain listing of the
	// bucket has no such uploads, however long that listing is.
	fake, store = plainFixture(t)
	fake.versions = false
	fake.uploadPage = func(int, string) string { return plain }
	if deleted, err := store.DeleteBucket(ctx, Bucket{Name: "helios-site"}, Check{NotWrittenSince: removedAt}); err != nil || !deleted.Bucket {
		t.Fatalf("a store without unfinished uploads: deleted %+v, error %v", deleted, err)
	}

	for name, broken := range map[string]struct {
		page func(n int, marker string) string
		want string
	}{
		"the same marker again": {func(int, string) string { return more("data/cc/half", "u1", upload("data/cc/half", "u1")) }, "the store named a marker it had already passed"},
		"a marker further back": {func(n int, _ string) string {
			return more(fmt.Sprintf("data/%c", 'z'-rune(n)), fmt.Sprintf("u%d", n), upload("data/cc/half", "u1"))
		}, "the store named a marker it had already passed"},
		"pages of nothing": {func(n int, _ string) string { return more(fmt.Sprintf("k%04d", n), "", "") }, "pages in a row held nothing and said there was more"},
		"a plain listing after uploads": {func(n int, _ string) string {
			if n == 1 {
				return more("data/cc/half", "u1", upload("data/cc/half", "u1"))
			}
			return plain
		}, "which is not a listing of the bucket"},
		"an answer that is no listing": {func(int, string) string { return `<Ok/>` }, "which is not a listing of the bucket"},
	} {
		// A listing that goes round is stopped by the clock, and fails here.
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		fake, store := s3Fixture(t)
		fake.uploadPage = broken.page
		_, err := store.DeleteBucket(ctx, Bucket{Name: "helios-site"}, Check{NotWrittenSince: removedAt})
		if err == nil || !strings.Contains(err.Error(), broken.want) || len(fake.deletes) != 0 {
			t.Fatalf("%s: delete error %v, deletes %v", name, err, fake.deletes)
		}
		if fake.uploadLists > 4*s3EmptyPages {
			t.Fatalf("%s: the uploads were listed %d times", name, fake.uploadLists)
		}
		cancel()
	}
}

// One name may have more versions than a page holds. The listing then
// carries on after the same name and a new version each time, which is not
// a marker it has passed.
func TestS3VersionListingCarriesOnThroughOneNamesVersions(t *testing.T) {
	var asked []string
	pages := map[string]string{
		"":   `<ListVersionsResult><IsTruncated>true</IsTruncated><NextKeyMarker>a</NextKeyMarker><NextVersionIdMarker>v1</NextVersionIdMarker><Version><Key>a</Key><VersionId>v1</VersionId><Size>1</Size></Version></ListVersionsResult>`,
		"v1": `<ListVersionsResult><IsTruncated>true</IsTruncated><NextKeyMarker>a</NextKeyMarker><NextVersionIdMarker>v2</NextVersionIdMarker><Version><Key>a</Key><VersionId>v2</VersionId><Size>2</Size></Version></ListVersionsResult>`,
		"v2": `<ListVersionsResult><IsTruncated>false</IsTruncated><Version><Key>b</Key><VersionId>v3</VersionId><Size>4</Size></Version></ListVersionsResult>`,
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		at := r.URL.Query().Get("version-id-marker")
		asked = append(asked, r.URL.Query().Get("key-marker")+"@"+at)
		fmt.Fprint(w, pages[at])
	}))
	t.Cleanup(server.Close)
	store, err := New(Config{Kind: "s3", Endpoint: server.URL + "/", KeyID: "id", Key: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	usage, err := store.Usage(context.Background(), Bucket{Name: "helios-site"})
	if err != nil {
		t.Fatal(err)
	}
	if usage.Files != 3 || usage.Bytes != 7 {
		t.Fatalf("usage: %+v", usage)
	}
	if strings.Join(asked, " ") != "@ a@v1 a@v2" {
		t.Fatalf("asked %v", asked)
	}
}

// Only the first thing a store says about versions decides how it is read.
// One that listed versions and then answers with a plain listing, or
// refuses, is not read through the plain listing: that shows the newest
// version of each file and would leave the others out.
func TestS3ThatListedVersionsIsNeverReadThroughThePlainListing(t *testing.T) {
	ctx := context.Background()
	for name, turn := range map[string]func(*fakeS3){
		"a plain answer": func(f *fakeS3) { f.ignoresVersions = true },
		"a refusal":      func(f *fakeS3) { f.versions = false },
	} {
		fake, store := s3Fixture(t)
		fake.page = 10
		if usage, err := store.Usage(ctx, Bucket{Name: "helios-site"}); err != nil || usage.Files != 5 {
			t.Fatalf("%s: usage %+v %v", name, usage, err)
		}
		fake.mu.Lock()
		turn(fake)
		fake.mu.Unlock()
		if _, err := store.Usage(ctx, Bucket{Name: "helios-site"}); err == nil || !strings.Contains(err.Error(), "the store listed versions and now") {
			t.Fatalf("%s: usage error %v", name, err)
		}
		_, err := store.DeleteBucket(ctx, Bucket{Name: "helios-site"}, Check{NotWrittenSince: removedAt})
		if err == nil || !strings.Contains(err.Error(), "the store listed versions and now") || len(fake.deletes) != 0 {
			t.Fatalf("%s: delete error %v, deletes %v", name, err, fake.deletes)
		}
	}
}

// An answer that is no listing at all is an error, not an empty bucket.
func TestS3AnswerThatIsNotAListingIsNotAnEmptyBucket(t *testing.T) {
	ctx := context.Background()
	for name, answer := range map[string]string{
		"nothing":          "",
		"something else":   `<ListAllMyBucketsResult><Buckets></Buckets></ListAllMyBucketsResult>`,
		"a page of a site": `<html><body>welcome</body></html>`,
	} {
		for _, plain := range []bool{false, true} {
			fake, store := s3Fixture(t)
			fake.answer, store.(*s3).plain = &answer, plain
			usage, err := store.Usage(ctx, Bucket{Name: "helios-site"})
			if err == nil || !strings.Contains(err.Error(), "the store answered with") {
				t.Fatalf("%s (plain %t): usage %+v, error %v", name, plain, usage, err)
			}
			if err := store.Examine(ctx, Bucket{Name: "helios-site"}, Check{}); err == nil {
				t.Fatalf("%s (plain %t): the bucket passed as empty", name, plain)
			}
			deleted, err := store.DeleteBucket(ctx, Bucket{Name: "helios-site"}, Check{})
			if err == nil || deleted.Bucket || len(fake.deletes) != 0 {
				t.Fatalf("%s (plain %t): deleted %+v %v, error %v", name, plain, deleted, fake.deletes, err)
			}
		}
	}
}
