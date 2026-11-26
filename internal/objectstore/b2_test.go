package objectstore

import (
	"context"
	"encoding/json"
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

type fakeB2File struct {
	id, name, action string
	size             int64
	at               time.Time
}

// fakeB2 answers the native API calls the client makes, with the field
// names and the error shape Backblaze documents for v4.
type fakeB2 struct {
	t        *testing.T
	mu       sync.Mutex
	server   *httptest.Server
	buckets  map[string]string // id -> name
	files    map[string][]fakeB2File
	page     int
	tokens   int
	expire   bool
	busy     int
	deletes  []string
	refuseAt string
}

func (f *fakeB2) fail(w http.ResponseWriter, status int, code string) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"status": status, "code": code, "message": code + " happened"})
}

func (f *fakeB2) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	call := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
	if !strings.HasPrefix(r.URL.Path, "/b2api/v4/") {
		f.t.Errorf("unexpected path %s", r.URL.Path)
	}
	if call == "b2_authorize_account" {
		id, key, ok := r.BasicAuth()
		if !ok || id != "key-id" || key != "key-secret" {
			f.fail(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		f.tokens++
		json.NewEncoder(w).Encode(map[string]any{
			"accountId": "acct-1", "authorizationToken": fmt.Sprintf("token-%d", f.tokens),
			"apiInfo": map[string]any{"storageApi": map[string]any{"apiUrl": f.server.URL, "allowed": map[string]any{"capabilities": []string{"listBuckets"}}}},
		})
		return
	}
	if r.Header.Get("Authorization") != fmt.Sprintf("token-%d", f.tokens) {
		f.fail(w, http.StatusUnauthorized, "bad_auth_token")
		return
	}
	if f.expire {
		f.expire = false
		f.tokens++ // the old token stops working
		f.fail(w, http.StatusUnauthorized, "expired_auth_token")
		return
	}
	if f.busy > 0 {
		f.busy--
		f.fail(w, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	var in struct {
		AccountID     string `json:"accountId"`
		BucketID      string `json:"bucketId"`
		StartFileName string `json:"startFileName"`
		StartFileID   string `json:"startFileId"`
		MaxFileCount  int    `json:"maxFileCount"`
		FileName      string `json:"fileName"`
		FileID        string `json:"fileId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		f.fail(w, http.StatusBadRequest, "bad_request")
		return
	}
	switch call {
	case "b2_list_buckets":
		if in.AccountID != "acct-1" {
			f.fail(w, http.StatusBadRequest, "bad_request")
			return
		}
		var out []map[string]any
		for id, name := range f.buckets {
			out = append(out, map[string]any{"accountId": "acct-1", "bucketId": id, "bucketName": name, "bucketType": "allPrivate"})
		}
		sort.Slice(out, func(i, j int) bool { return out[i]["bucketName"].(string) < out[j]["bucketName"].(string) })
		json.NewEncoder(w).Encode(map[string]any{"buckets": out})
	case "b2_list_file_versions":
		files, ok := f.files[in.BucketID]
		if !ok {
			f.fail(w, http.StatusBadRequest, "bad_bucket_id")
			return
		}
		if in.MaxFileCount != b2Page {
			f.t.Errorf("maxFileCount %d", in.MaxFileCount)
		}
		sorted := append([]fakeB2File{}, files...)
		sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].name < sorted[j].name })
		start := 0
		if in.StartFileName != "" {
			for start < len(sorted) && !(sorted[start].name == in.StartFileName && sorted[start].id == in.StartFileID) && sorted[start].name <= in.StartFileName {
				start++
			}
		}
		end := min(start+f.page, len(sorted))
		var out []map[string]any
		for _, file := range sorted[start:end] {
			// Backblaze's own examples quote these integers; the schema
			// says they are numbers. The client reads both.
			out = append(out, map[string]any{"fileId": file.id, "fileName": file.name, "action": file.action,
				"contentLength": file.size, "uploadTimestamp": fmt.Sprint(file.at.UnixMilli())})
		}
		answer := map[string]any{"files": out, "nextFileName": nil, "nextFileId": nil}
		if end < len(sorted) {
			answer["nextFileName"], answer["nextFileId"] = sorted[end].name, sorted[end].id
		}
		json.NewEncoder(w).Encode(answer)
	case "b2_delete_file_version":
		if in.FileID == f.refuseAt {
			f.fail(w, http.StatusUnauthorized, "access_denied")
			return
		}
		for bucket, files := range f.files {
			for i, file := range files {
				if file.id == in.FileID && file.name == in.FileName {
					f.files[bucket] = append(append([]fakeB2File{}, files[:i]...), files[i+1:]...)
					f.deletes = append(f.deletes, file.name+"@"+file.id)
					json.NewEncoder(w).Encode(map[string]any{"fileId": in.FileID, "fileName": in.FileName})
					return
				}
			}
		}
		f.fail(w, http.StatusBadRequest, "file_not_present")
	case "b2_delete_bucket":
		if len(f.files[in.BucketID]) > 0 {
			f.fail(w, http.StatusBadRequest, "cannot_delete_non_empty_bucket")
			return
		}
		f.deletes = append(f.deletes, "bucket "+f.buckets[in.BucketID])
		delete(f.buckets, in.BucketID)
		delete(f.files, in.BucketID)
		json.NewEncoder(w).Encode(map[string]any{"bucketId": in.BucketID})
	default:
		f.t.Errorf("unexpected call %s", call)
		f.fail(w, http.StatusBadRequest, "bad_request")
	}
}

func b2Fixture(t *testing.T) (*fakeB2, Store) {
	t.Helper()
	old := removedAt.Add(-24 * time.Hour)
	fake := &fakeB2{t: t, page: 2, buckets: map[string]string{"b-site": "helios-site", "b-other": "helios-other"}, files: map[string][]fakeB2File{
		"b-site": {
			{id: "f1", name: "config", action: "upload", size: 100, at: old},
			// Two versions of one name: both are billed, both must go.
			{id: "f2", name: "data/aa/pack", action: "upload", size: 4000, at: old},
			{id: "f3", name: "data/aa/pack", action: "upload", size: 4000, at: old.Add(-time.Hour)},
			{id: "f4", name: "data/bb/gone", action: "hide", size: 0, at: old.Add(time.Hour)},
			{id: "f5", name: "data/cc/half", action: "start", size: 0, at: old},
		},
		"b-other": {{id: "o1", name: "config", action: "upload", size: 7, at: removedAt.Add(time.Hour)}},
	}}
	fake.server = httptest.NewServer(fake)
	t.Cleanup(fake.server.Close)
	store, err := New(Config{KeyID: "key-id", Key: "key-secret"})
	if err != nil {
		t.Fatal(err)
	}
	client := store.(*b2)
	client.authURL = fake.server.URL + "/b2api/v4/b2_authorize_account"
	client.wait = func(context.Context, int) error { return nil }
	return fake, store
}

func TestB2ListsBucketsAndAddsUpEveryVersion(t *testing.T) {
	ctx := context.Background()
	fake, store := b2Fixture(t)
	fake.busy = 1
	account, err := store.Account(ctx)
	if err != nil || account != "b2:acct-1" {
		t.Fatalf("account %q %v", account, err)
	}
	buckets, err := store.Buckets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(buckets) != 2 || buckets[1] != (Bucket{Name: "helios-site", ID: "b-site"}) {
		t.Fatalf("buckets: %v", buckets)
	}
	fake.expire = true // the token runs out mid-session; the client signs in again
	usage, err := store.Usage(ctx, buckets[1])
	if err != nil {
		t.Fatal(err)
	}
	if usage.Bytes != 8100 || usage.Files != 5 || !usage.LastWrite.Equal(removedAt.Add(-23*time.Hour)) {
		t.Fatalf("usage: %+v", usage)
	}
	if fake.tokens != 3 {
		t.Fatalf("signed in %d times", fake.tokens)
	}
	if _, err := store.Usage(ctx, Bucket{Name: "helios-site"}); err == nil {
		t.Fatal("usage without a bucket id succeeded")
	}
}

func TestB2DeletesEveryVersionThenTheBucket(t *testing.T) {
	ctx := context.Background()
	fake, store := b2Fixture(t)
	deleted, err := store.DeleteBucket(ctx, Bucket{Name: "helios-site", ID: "b-site"}, Check{NotWrittenSince: removedAt})
	if err != nil {
		t.Fatal(err)
	}
	if !deleted.Bucket || deleted.Files != 5 || deleted.Bytes != 8100 {
		t.Fatalf("deleted: %+v", deleted)
	}
	want := "config@f1|data/aa/pack@f2|data/aa/pack@f3|data/bb/gone@f4|data/cc/half@f5|bucket helios-site"
	if got := strings.Join(fake.deletes, "|"); got != want {
		t.Fatalf("deletes: %s", got)
	}
	if len(fake.files["b-other"]) != 1 || fake.buckets["b-other"] == "" {
		t.Fatal("another bucket was touched")
	}
}

func TestB2DeletesNothingFromABucketWrittenSince(t *testing.T) {
	ctx := context.Background()
	fake, store := b2Fixture(t)
	// The write that gives it away is on the last page.
	fake.files["b-site"] = append(fake.files["b-site"], fakeB2File{id: "f9", name: "snapshots/new", action: "upload", size: 1, at: removedAt.Add(time.Minute)})
	deleted, err := store.DeleteBucket(ctx, Bucket{Name: "helios-site", ID: "b-site"}, Check{NotWrittenSince: removedAt})
	if !errors.Is(err, ErrWrittenSince) {
		t.Fatalf("error: %v", err)
	}
	if deleted.Files != 0 || deleted.Bucket || len(fake.deletes) != 0 || len(fake.files["b-site"]) != 6 {
		t.Fatalf("something was deleted: %+v %v", deleted, fake.deletes)
	}
}

func TestB2StopsAtARefusedDeleteAndCanBeRunAgain(t *testing.T) {
	ctx := context.Background()
	fake, store := b2Fixture(t)
	fake.refuseAt = "f3"
	deleted, err := store.DeleteBucket(ctx, Bucket{Name: "helios-site", ID: "b-site"}, Check{NotWrittenSince: removedAt})
	var refusal *APIError
	if !errors.As(err, &refusal) || refusal.Code != "access_denied" {
		t.Fatalf("error: %v", err)
	}
	if deleted.Bucket || fake.buckets["b-site"] == "" {
		t.Fatal("the bucket went although a file could not be deleted")
	}
	fake.refuseAt = ""
	deleted, err = store.DeleteBucket(ctx, Bucket{Name: "helios-site", ID: "b-site"}, Check{NotWrittenSince: removedAt})
	if err != nil || !deleted.Bucket {
		t.Fatalf("second run: %+v %v", deleted, err)
	}
	if fake.buckets["b-site"] != "" {
		t.Fatal("the bucket is still there")
	}
}

func TestB2WrongKeyIsReported(t *testing.T) {
	fake, _ := b2Fixture(t)
	store, _ := New(Config{KeyID: "key-id", Key: "wrong"})
	client := store.(*b2)
	client.authURL = fake.server.URL + "/b2api/v4/b2_authorize_account"
	_, err := store.Buckets(context.Background())
	var refusal *APIError
	if !errors.As(err, &refusal) || refusal.Status != http.StatusUnauthorized {
		t.Fatalf("error: %v", err)
	}
}

// A check on the bucket's contents refuses before anything is deleted,
// whether it objects to one name or to the bucket as a whole, and is asked
// again about each page as it goes.
func TestB2DeletesNothingFromABucketItsCheckRefuses(t *testing.T) {
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
		fake, store := b2Fixture(t)
		for _, try := range []func() error{
			func() error { return store.Examine(ctx, Bucket{Name: "helios-site", ID: "b-site"}, check) },
			func() error {
				_, err := store.DeleteBucket(ctx, Bucket{Name: "helios-site", ID: "b-site"}, check)
				return err
			},
		} {
			if err := try(); !errors.Is(err, refusal) {
				t.Fatalf("%s: error %v", name, err)
			}
			if len(fake.deletes) != 0 || len(fake.files["b-site"]) != 5 {
				t.Fatalf("%s: something was deleted: %v", name, fake.deletes)
			}
		}
	}

	// What passes is read whole, judged once, and then every name is asked
	// about a second time on its way out.
	fake, store := b2Fixture(t)
	seen, judged := map[string]int{}, 0
	check := Check{Key: func(key string) error { seen[key]++; return nil }, Whole: func() error {
		judged++
		if len(fake.deletes) != 0 {
			t.Fatal("judged after the deletion began")
		}
		return nil
	}}
	if err := store.Examine(ctx, Bucket{Name: "helios-site", ID: "b-site"}, check); err != nil || len(fake.deletes) != 0 || judged != 1 {
		t.Fatalf("examine: %v, deletes %v, judged %d", err, fake.deletes, judged)
	}
	if _, err := store.DeleteBucket(ctx, Bucket{Name: "helios-site", ID: "b-site"}, check); err != nil || judged != 2 {
		t.Fatalf("delete: %v, judged %d", err, judged)
	}
	if seen["config"] != 3 {
		t.Fatalf("config was asked about %d times, want once to examine, once to read and once to delete: %v", seen["config"], seen)
	}
}
