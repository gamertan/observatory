// SPDX-License-Identifier: AGPL-3.0-only

// Package site contains Observatory's typed Sandwich Hime interface and its
// immutable browser assets. HTTP policy remains owned by internal/httpserver.
package site

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
)

//go:embed assets/site.css
var style []byte

//go:embed assets/site.js
var script []byte

//go:embed assets/observatory.svg
var icon []byte

type Assets struct {
	StylePath  string
	ScriptPath string
	IconPath   string
}

func AssetPaths() Assets {
	return Assets{StylePath: fingerprintedPath("site", "css", style), ScriptPath: fingerprintedPath("site", "js", script), IconPath: fingerprintedPath("observatory", "svg", icon)}
}

func Asset(path string) (body []byte, contentType string, ok bool) {
	assets := AssetPaths()
	switch path {
	case assets.StylePath:
		return style, "text/css; charset=utf-8", true
	case assets.ScriptPath:
		return script, "text/javascript; charset=utf-8", true
	case assets.IconPath:
		return icon, "image/svg+xml", true
	default:
		return nil, "", false
	}
}

func fingerprintedPath(name, extension string, body []byte) string {
	digest := sha256.Sum256(body)
	return "/assets/" + name + "-" + hex.EncodeToString(digest[:8]) + "." + extension
}
