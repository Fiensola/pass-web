package entries

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/fiensola/pass-web/internal/crypto"
)

const entriesFilename = "entries.json"

func entiresPath(vaultDir string) string {
	return filepath.Join(vaultDir, entriesFilename)
}

func Save(vauldDir string, entries []Entry, masterPassword string, salt string) error {
	data, err := json.Marshal(entries)
	if err != nil {
		return err
	}

	encrypted, err := crypto.Encrypt(data, masterPassword, salt)
	if err != nil {
		return err
	}

	return os.WriteFile(entiresPath(vauldDir), []byte(encrypted), 0600)
}

func Load(vauldDir string, masterPassword string, salt string) ([]Entry, error) {
	encryptedData, err := os.ReadFile(entiresPath(vauldDir))
	if err != nil {
		if os.IsNotExist(err) {
			return []Entry{}, nil
		}

		return nil, err
	}

	if len(encryptedData) == 0 {
		return []Entry{}, nil
	}

	decrypted, err := crypto.Decrypt(string(encryptedData), masterPassword, salt)
	if err != nil {
		return nil, err
	}

	var entries []Entry
	err = json.Unmarshal(decrypted, &entries)
	if err != nil {
		return nil, err
	}

	return entries, nil
}