package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
)

const metaFilename = "meta.json"

type Meta struct {
	MasterHash string `json:"master_hash"`
	DataSalt   string `json:"data_salt"`
}

func metaPath(vaultDir string) string {
	return filepath.Join(vaultDir, metaFilename)
}

func Save(vaultDir string, hash string) error {

	salt := make([]byte, 32)
	rand.Read(salt)
	dataSalt := base64.RawStdEncoding.EncodeToString(salt)

	meta := Meta{
		MasterHash: hash,
		DataSalt: dataSalt,
	}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(metaPath(vaultDir), data, 0600)
}

func Load(vauldDir string) (Meta, error) {
	data, err := os.ReadFile(metaPath(vauldDir))
	if err != nil {
		if os.IsNotExist(err) {
			return Meta{}, nil //first run
		}

		return Meta{}, err
	}

	var meta Meta
	if err := json.Unmarshal(data, &meta); err != nil {
		return Meta{}, err
	}

	return meta, nil
}
