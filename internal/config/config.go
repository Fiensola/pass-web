package config

import (
	"flag"
)

type Config struct {
	Port     string
	VaultDir string
}

func Load() *Config {
	port := flag.String("port", "8080", "server port")
	vaultDir := flag.String("vault", "./vault", "path to vault dir")
	flag.Parse()

	return &Config{
		Port:     *port,
		VaultDir: *vaultDir,
	}
}
