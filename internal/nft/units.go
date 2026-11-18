package nft

import (
	"embed"
	"io/fs"
)

//go:embed units/*
var unitFS embed.FS

// Units returns the systemd unit files, file name → text: supapace-nft.service
// and supapaced.service go to the systemd unit directory, docker-10-supapace.conf
// is the drop-in docker.service.d/10-supapace.conf.
func Units() map[string][]byte {
	ents, _ := fs.ReadDir(unitFS, "units") // embedded: cannot fail
	m := make(map[string][]byte, len(ents))
	for _, e := range ents {
		b, _ := unitFS.ReadFile("units/" + e.Name())
		m[e.Name()] = b
	}
	return m
}
