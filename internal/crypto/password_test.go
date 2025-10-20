package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHashPassword(t *testing.T) {
	password := "my-pass!"

	hash, err := HashPassword(password)
	assert.NoError(t, err)
	assert.NotEmpty(t, hash)
	assert.Contains(t, hash, "argon2id$")

	valid, err := VerifyPassword(password, hash)
	assert.NoError(t, err)
	assert.True(t, valid)

	valid, err = VerifyPassword("fake-pass!", hash)
	assert.NoError(t, err)
	assert.False(t, valid)

	valid, err = VerifyPassword(password, "fake-hash")
	assert.Error(t, err)
	assert.False(t, valid)
}
