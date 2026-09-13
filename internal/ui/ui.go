// Package ui menanamkan aset web UI HeaderGuard ke dalam binary.
package ui

import (
	"embed"
	"io/fs"
)

//go:embed index.html css/style.css js/app.js
var assets embed.FS

// Assets mengembalikan sistem file statis untuk web UI.
func Assets() fs.FS {
	sub, err := fs.Sub(assets, ".")
	if err != nil {
		panic(err) // tidak mungkin terjadi: embed selalu valid
	}
	return sub
}
