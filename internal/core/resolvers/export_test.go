// export_test.go — test-only seams for the resolvers package.
//
// Compiled only under `go test`, so nothing here exists in a production build.

package resolvers

import (
	"net/http"
	"testing"
)

// SetDownloadClientForTest points resolver downloads at c for the duration of
// the test. Needed because httpDownload refuses any non-HTTPS URL, so a test
// mirror must be an httptest TLS server and its self-signed certificate is only
// trusted by the client that server hands out.
func SetDownloadClientForTest(t *testing.T, c *http.Client) {
	t.Helper()
	prev := newDownloadClient
	newDownloadClient = func() *http.Client { return c }
	t.Cleanup(func() { newDownloadClient = prev })
}
