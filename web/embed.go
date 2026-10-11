// Package web embeds the built frontend (web/dist) so that the Go binary can
// serve it without any files next to it.
//
// Build the frontend first with "npm run build" in this directory. The dist
// directory always holds a tracked .gitkeep, so the module compiles on a fresh
// clone; until the frontend is built the server shows a hint instead of the UI.
package web

import (
	"embed"
	"fmt"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Dist returns the built frontend, rooted at the contents of web/dist.
func Dist() (fs.FS, error) {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return nil, fmt.Errorf("open embedded frontend: %w", err)
	}
	return sub, nil
}
