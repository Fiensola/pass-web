package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
)

const metaFilename = "meta.json"

type Meta struct {
	MasterHash string `json:"master_hash"`
}

func metaPath(vaultDir string) string {
	return filepath.Join(vaultDir, metaFilename)
}

func Save(vaultDir string, hash string) error {
	meta := Meta{MasterHash: hash}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(metaPath(vaultDir), data, 0600)
}

func Load(vauldDir string) (string, error) {
	data, err := os.ReadFile(metaPath(vauldDir))
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil //first run
		}

		return "", err
	}

	var meta Meta
	if err := json.Unmarshal(data, &meta); err != nil {
		return "", err
	}

	return meta.MasterHash, nil
}
