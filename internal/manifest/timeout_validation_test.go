package manifest

import (
	"fmt"
	"strings"
	"testing"
)

func TestJobTimeoutsMustBePositiveWhenDeclared(t *testing.T) {
	for _, kind := range []Kind{Cron, Release} {
		for _, timeout := range []string{"0", "0s", "-1s", "1s", ""} {
			t.Run(string(kind)+"/"+timeout, func(t *testing.T) {
				schedule := ""
				if kind == Cron {
					schedule = "    schedule: '0 3 * * *'\n"
				}
				body := fmt.Sprintf("app: site\nworkloads:\n  job:\n    kind: %s\n    image: image\n%s    timeout: %q\n", kind, schedule, timeout)
				_, err := Parse([]byte(body))
				if timeout == "" || timeout == "1s" {
					if err != nil {
						t.Fatal(err)
					}
				} else if err == nil || !strings.Contains(err.Error(), "workloads.job.timeout") {
					t.Fatalf("accepted nonpositive timeout: %v", err)
				}
			})
		}
	}
}
