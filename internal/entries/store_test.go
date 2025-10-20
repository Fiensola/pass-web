package entries

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSaveLoad(t *testing.T) {
	tempDir := t.TempDir()
	vauldDir := filepath.Join(tempDir, "vault")
	err := os.MkdirAll(vauldDir, 0700)
	assert.NoError(t, err)

	password := "my-pass"
	salt := base64.RawStdEncoding.EncodeToString([]byte("my-salt"))

	entry := Entry{
		ID:        NewID(),
		Title:     "Test Service",
		URL:       "https://example.com",
		Username:  "user123",
		Password:  "pass123",
		Notes:     "Test entry",
		CreatedAt: time.Now(),
	}

	err = Save(vauldDir, []Entry{entry}, password, salt)
	assert.NoError(t, err)

	loaded, err := Load(vauldDir, password, salt)
	assert.NoError(t, err)
	assert.Len(t, loaded, 1)
	assert.Equal(t, entry.Title, loaded[0].Title)
	assert.Equal(t, entry.Username, loaded[0].Username)
	assert.Equal(t, entry.Password, loaded[0].Password)
}

func TestLoadEntries_Empty(t *testing.T) {
	tempDir := t.TempDir()
	vaultDir := filepath.Join(tempDir, "vault")
	os.MkdirAll(vaultDir, 0700)

	salt := base64.RawStdEncoding.EncodeToString([]byte("my-salt"))
	password := "my-pass"

	entries, err := Load(vaultDir, password, salt)
	assert.NoError(t, err)
	assert.Empty(t, entries)
}
