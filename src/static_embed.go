package main

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static
var embeddedStaticFiles embed.FS

func newStaticFileServer() http.Handler {
	staticFS, err := fs.Sub(embeddedStaticFiles, "static")
	if err != nil {
		panic(err)
	}
	return http.FileServer(http.FS(staticFS))
}
