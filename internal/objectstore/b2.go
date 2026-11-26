package objectstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// b2AuthURL is where every Backblaze B2 session starts. The answer names
// the API host the account lives on.
const b2AuthURL = "https://api.backblazeb2.com/b2api/v4/b2_authorize_account"

// b2Page is how many file versions one listing call asks for. Backblaze
// bills a listing per thousand files returned, so a larger page saves
// nothing.
const b2Page = 1000

type b2 struct {
	keyID, key string
	authURL    string
	http       *http.Client
	wait       func(context.Context, int) error

	// Set by authorize.
	account, token, api string
}

// b2Int reads an integer Backblaze may send as a number or, as its own
// examples show, as a quoted string.
type b2Int int64

func (n *b2Int) UnmarshalJSON(data []byte) error {
	text := strings.Trim(string(data), `"`)
	if text == "" || text == "null" {
		*n = 0
		return nil
	}
	v, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return fmt.Errorf("not an integer: %s", data)
	}
	*n = b2Int(v)
	return nil
}

func (c *b2) authorize(ctx context.Context) error {
	var out struct {
		AccountID string `json:"accountId"`
		Token     string `json:"authorizationToken"`
		APIInfo   struct {
			Storage struct {
				APIURL string `json:"apiUrl"`
			} `json:"storageApi"`
		} `json:"apiInfo"`
	}
	req := func() (*http.Request, error) {
		r, err := http.NewRequestWithContext(ctx, http.MethodGet, c.authURL, nil)
		if err != nil {
			return nil, err
		}
		r.SetBasicAuth(c.keyID, c.key)
		return r, nil
	}
	if err := c.send(ctx, req, &out); err != nil {
		return fmt.Errorf("authorize with Backblaze: %w", err)
	}
	api := strings.TrimSuffix(out.APIInfo.Storage.APIURL, "/")
	if out.AccountID == "" || out.Token == "" || !strings.HasPrefix(api, "http") {
		return errors.New("authorize with Backblaze: the answer names no account, token or API address")
	}
	c.account, c.token, c.api = out.AccountID, out.Token, api
	return nil
}

// send runs one request, retrying while the store says it is busy.
func (c *b2) send(ctx context.Context, build func() (*http.Request, error), out any) error {
	var last error
	for n := 0; n < attempts; n++ {
		if n > 0 {
			if err := c.wait(ctx, n-1); err != nil {
				return errors.Join(last, err)
			}
		}
		req, err := build()
		if err != nil {
			return err
		}
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
		if resp.StatusCode == http.StatusOK {
			if out == nil {
				return nil
			}
			if err := json.Unmarshal(body, out); err != nil {
				return fmt.Errorf("read storage answer: %w", err)
			}
			return nil
		}
		var refusal struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(body, &refusal)
		last = &APIError{Status: resp.StatusCode, Code: refusal.Code, Message: refusal.Message}
		if !retryable(resp.StatusCode) {
			return last
		}
	}
	return last
}

// call posts one API call, authorizing first and once more when the token
// has expired.
func (c *b2) call(ctx context.Context, name string, in, out any) error {
	if c.token == "" {
		if err := c.authorize(ctx); err != nil {
			return err
		}
	}
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	post := func() (*http.Request, error) {
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.api+"/b2api/v4/"+name, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		r.Header.Set("Authorization", c.token)
		r.Header.Set("Content-Type", "application/json")
		return r, nil
	}
	err = c.send(ctx, post, out)
	var refusal *APIError
	if errors.As(err, &refusal) && refusal.Status == http.StatusUnauthorized && (refusal.Code == "expired_auth_token" || refusal.Code == "bad_auth_token") {
		if err := c.authorize(ctx); err != nil {
			return err
		}
		err = c.send(ctx, post, out)
	}
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func (c *b2) Account(ctx context.Context) (string, error) {
	if c.account == "" {
		if err := c.authorize(ctx); err != nil {
			return "", err
		}
	}
	return "b2:" + c.account, nil
}

func (c *b2) Buckets(ctx context.Context) ([]Bucket, error) {
	if _, err := c.Account(ctx); err != nil {
		return nil, err
	}
	var out struct {
		Buckets []struct {
			ID   string `json:"bucketId"`
			Name string `json:"bucketName"`
		} `json:"buckets"`
	}
	if err := c.call(ctx, "b2_list_buckets", map[string]any{"accountId": c.account}, &out); err != nil {
		return nil, err
	}
	buckets := make([]Bucket, 0, len(out.Buckets))
	for _, b := range out.Buckets {
		if b.ID == "" || b.Name == "" {
			return nil, errors.New("b2_list_buckets: a bucket without a name or an id")
		}
		buckets = append(buckets, Bucket{Name: b.Name, ID: b.ID})
	}
	return buckets, nil
}

type b2File struct {
	ID       string `json:"fileId"`
	Name     string `json:"fileName"`
	Action   string `json:"action"`
	Length   b2Int  `json:"contentLength"`
	Uploaded b2Int  `json:"uploadTimestamp"`
}

// versions walks every file version in a bucket: uploads, hide markers and
// unfinished large files, which the listing reports as "start".
func (c *b2) versions(ctx context.Context, b Bucket, each func([]b2File) error) error {
	if b.ID == "" {
		return errors.New("a Backblaze bucket needs its id")
	}
	in := map[string]any{"bucketId": b.ID, "maxFileCount": b2Page}
	for {
		var out struct {
			Files        []b2File `json:"files"`
			NextFileName *string  `json:"nextFileName"`
			NextFileID   *string  `json:"nextFileId"`
		}
		if err := c.call(ctx, "b2_list_file_versions", in, &out); err != nil {
			return err
		}
		if err := each(out.Files); err != nil {
			return err
		}
		if out.NextFileName == nil {
			return nil
		}
		in["startFileName"] = *out.NextFileName
		delete(in, "startFileId")
		if out.NextFileID != nil {
			in["startFileId"] = *out.NextFileID
		}
	}
}

func (c *b2) Usage(ctx context.Context, b Bucket) (Usage, error) {
	var u Usage
	err := c.versions(ctx, b, func(files []b2File) error {
		for _, f := range files {
			u.Files++
			u.Bytes += int64(f.Length)
			if at := time.UnixMilli(int64(f.Uploaded)).UTC(); f.Uploaded > 0 && at.After(u.LastWrite) {
				u.LastWrite = at
			}
		}
		return nil
	})
	return u, err
}

func b2Checked(check Check) func([]b2File) error {
	return func(files []b2File) error {
		for _, f := range files {
			if err := check.file(f.Name, time.UnixMilli(int64(f.Uploaded))); err != nil {
				return err
			}
		}
		return nil
	}
}

func (c *b2) Examine(ctx context.Context, b Bucket, check Check) error {
	if err := c.versions(ctx, b, b2Checked(check)); err != nil {
		return err
	}
	return check.whole()
}

func (c *b2) DeleteBucket(ctx context.Context, b Bucket, check Check) (Deleted, error) {
	var d Deleted
	// Read the whole bucket before deleting any of it, so a bucket that
	// does not pass loses nothing. The pages are checked again below for
	// what arrives while the deletion runs.
	if err := c.Examine(ctx, b, check); err != nil {
		return d, err
	}
	checked := b2Checked(check)
	err := c.versions(ctx, b, func(files []b2File) error {
		if err := checked(files); err != nil {
			return err
		}
		for _, f := range files {
			if f.ID == "" {
				continue // a folder entry, which a listing without a delimiter never returns
			}
			err := c.call(ctx, "b2_delete_file_version", map[string]any{"fileName": f.Name, "fileId": f.ID}, nil)
			var refusal *APIError
			if errors.As(err, &refusal) && refusal.Code == "file_not_present" {
				continue // an earlier attempt deleted it
			}
			if err != nil {
				return err
			}
			d.Files++
			d.Bytes += int64(f.Length)
		}
		return nil
	})
	if err != nil {
		return d, err
	}
	if err := c.call(ctx, "b2_delete_bucket", map[string]any{"accountId": c.account, "bucketId": b.ID}, nil); err != nil {
		return d, err
	}
	d.Bucket = true
	return d, nil
}
