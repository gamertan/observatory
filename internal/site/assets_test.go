// SPDX-License-Identifier: AGPL-3.0-only

package site

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestAssetsAreContentAddressedAndBounded(t *testing.T) {
	paths := AssetPaths()
	for _, test := range []struct {
		path, suffix, contentType string
		body                      []byte
	}{{paths.StylePath, ".css", "text/css; charset=utf-8", style}, {paths.ScriptPath, ".js", "text/javascript; charset=utf-8", script}, {paths.IconPath, ".svg", "image/svg+xml", icon}} {
		t.Run(test.suffix, func(t *testing.T) {
			if len(test.body) == 0 || len(test.body) > 64<<10 || !strings.HasSuffix(test.path, test.suffix) {
				t.Fatalf("path=%q bytes=%d", test.path, len(test.body))
			}
			digest := sha256.Sum256(test.body)
			if !strings.Contains(test.path, hex.EncodeToString(digest[:8])) {
				t.Fatalf("asset path %q does not contain content digest", test.path)
			}
			body, contentType, ok := Asset(test.path)
			if !ok || contentType != test.contentType || string(body) != string(test.body) {
				t.Fatalf("asset lookup ok=%v type=%q", ok, contentType)
			}
		})
	}
	if _, _, ok := Asset("/assets/site.css"); ok {
		t.Fatal("unversioned asset path was accepted")
	}
	css := string(style)
	for _, required := range []string{"@media(max-width:24rem)", "@media(prefers-reduced-motion:reduce)", "@media(forced-colors:active)", "@media print", ".table-scroll", ".explore-layout", ".query-stats"} {
		if !strings.Contains(css, required) {
			t.Fatalf("responsive CSS missing %q", required)
		}
	}
	if strings.Contains(strings.ToLower(css), "position:sticky") {
		t.Fatal("mobile-hostile sticky table behavior returned")
	}
}
