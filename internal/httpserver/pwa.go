// SPDX-License-Identifier: AGPL-3.0-only

package httpserver

import (
	"fmt"
	"net/http"

	"gamertan.com/observatory/internal/site"
)

func (s *Server) webManifest(w http.ResponseWriter, r *http.Request) {
	serveFixedBody(w, r, site.WebManifest(), "application/manifest+json")
}

func (s *Server) serviceWorker(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Service-Worker-Allowed", "/")
	serveFixedBody(w, r, site.ServiceWorker(), "text/javascript; charset=utf-8")
}

func (s *Server) offlineShell(w http.ResponseWriter, r *http.Request) {
	s.renderHTML(w, r, http.StatusOK, site.Offline(site.OfflineView{Head: s.head("Offline — Gamertan Observatory", "Observatory is temporarily unreachable.", "/offline/")}))
}

func serveFixedBody(w http.ResponseWriter, r *http.Request, body []byte, contentType string) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}
