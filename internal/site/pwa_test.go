// SPDX-License-Identifier: AGPL-3.0-only

package site

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestManifestAndServiceWorkerUseExactContentAddressedShell(t *testing.T) {
	var manifest struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		StartURL string `json:"start_url"`
		Scope    string `json:"scope"`
		Display  string `json:"display"`
		Icons    []struct {
			Source  string `json:"src"`
			Sizes   string `json:"sizes"`
			Type    string `json:"type"`
			Purpose string `json:"purpose"`
		} `json:"icons"`
	}
	if err := json.Unmarshal(WebManifest(), &manifest); err != nil {
		t.Fatal(err)
	}
	assets := AssetPaths()
	if manifest.ID != "/app/" || manifest.Name != "Gamertan Observatory" || manifest.StartURL != "/app/" || manifest.Scope != "/" || manifest.Display != "standalone" || len(manifest.Icons) != 1 || manifest.Icons[0].Source != assets.IconPath || manifest.Icons[0].Sizes != "any" || manifest.Icons[0].Type != "image/svg+xml" || manifest.Icons[0].Purpose != "any maskable" {
		t.Fatalf("manifest=%+v", manifest)
	}

	worker := string(ServiceWorker())
	for _, required := range []string{"/offline/", assets.StylePath, assets.ScriptPath, assets.IconPath, "cache-inbox", "clear-private", "credentials:\"include\"", "source.pathname === \"/app/incidents/offline/\"", "target.pathname === \"/app/incidents/\"", "Gamertan Observatory needs your attention.", `self.addEventListener("push"`, `self.addEventListener("notificationclick"`, `data:{url:"/app/"}`} {
		if !strings.Contains(worker, required) {
			t.Fatalf("service worker missing %q", required)
		}
	}
	for _, forbidden := range []string{"query_text", "csrf_token", "telemetry", "incident.title", "organization_id", "service_id", "severity", "rule_id", "console.log", "eval("} {
		if strings.Contains(worker, forbidden) {
			t.Fatalf("service worker contains forbidden %q", forbidden)
		}
	}
	if strings.Count(worker, "Gamertan Observatory needs your attention.") != 1 {
		t.Fatal("service worker did not contain exactly one fixed notification message")
	}
	if first, second := string(ServiceWorker()), string(ServiceWorker()); first != second {
		t.Fatal("service worker output is not deterministic")
	}
}
