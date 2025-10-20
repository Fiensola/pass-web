package crypto

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncrypteDecryptData(t *testing.T) {
	plainText := []byte("Secret data")
	password := "my-pass"
	salt := base64.RawStdEncoding.EncodeToString([]byte("my-salt"))

	encrypted, err := Encrypt(plainText, password, salt)
	assert.NoError(t, err)
	assert.NotEmpty(t, encrypted)

	decrypted, err := Decrypt(encrypted, password, salt)
	assert.NoError(t, err)
	assert.Equal(t, plainText, decrypted)

	// wrong pass
	_, err = Decrypt(encrypted, "fake-pass", salt)
	assert.Error(t, err)

	// invalid input

	_, err = Decrypt("invalid-input", password, salt)
	assert.Error(t, err)
}
