package integration

import (
	"strings"
	"testing"
)

func TestIntegrationEndpointsRejectUndialableAndCredentialURLs(t *testing.T) {
	for _, endpoint := range []string{"https://", "http:///missing-host", "https://api.invalid:0", "https://api.invalid:65536", "https://user:private-password@api.invalid/base", "https://api.invalid/base#fragment"} {
		t.Run(endpoint, func(t *testing.T) {
			for _, name := range []string{StorageName, CloudflareName, LoomName} {
				values := map[string]string{"kind": "s3", "bucket_prefix": "test", "endpoint": endpoint, "api": endpoint, "verify_url": endpoint + "/verify"}
				err := validate(name, values)
				if err == nil {
					t.Errorf("%s accepted invalid endpoint", name)
				} else if strings.Contains(err.Error(), "private-password") {
					t.Errorf("%s disclosed embedded password", name)
				}
			}
		})
	}
}

func TestIntegrationEndpointsAllowHTTPPathsAndIPv6(t *testing.T) {
	for _, endpoint := range []string{"http://127.0.0.1:9000/base", "https://[::1]:443/base", "https://api.example.invalid/base"} {
		for _, name := range []string{StorageName, CloudflareName, LoomName} {
			if err := validate(name, map[string]string{"kind": "s3", "bucket_prefix": "test", "endpoint": endpoint, "api": endpoint, "verify_url": endpoint + "/verify"}); err != nil {
				t.Errorf("%s valid endpoint %s: %v", name, endpoint, err)
			}
		}
	}
}

func TestBaseEndpointsRejectQueriesWithoutDisclosingTheirValues(t *testing.T) {
	const hidden = "fixture-private-query"
	for _, endpoint := range []string{"https://api.example.com/base?token=" + hidden, "https://api.example.com/base?"} {
		for _, name := range []string{StorageName, CloudflareName} {
			values := map[string]string{"kind": "s3", "bucket_prefix": "test", "endpoint": endpoint, "api": endpoint}
			err := validate(name, values)
			if err == nil {
				t.Errorf("%s accepted a query in a base URL that appends paths", name)
			} else if strings.Contains(err.Error(), hidden) {
				t.Errorf("%s disclosed the query value", name)
			}
		}
	}
}
