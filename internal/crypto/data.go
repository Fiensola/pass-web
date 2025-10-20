package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

func deriveKey(password string, saltB64 string) []byte {
	salt, err := base64.RawStdEncoding.DecodeString(saltB64)
	if err != nil {
		panic("invalid data salt")
	}

	return argon2.IDKey(
		[]byte(password),
		salt,
		3,
		64*1024,
		2,
		32,
	)
}

func Encrypt(plainText []byte, password, saltB64 string) (string, error) {
	key := deriveKey(password, saltB64)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	cipherText := gcm.Seal(nonce, nonce, plainText, nil)

	return base64.URLEncoding.EncodeToString(cipherText), nil
}

func Decrypt(encryptedData string, password, saltB64 string) ([]byte, error) {
	data, err := base64.URLEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}

	key := deriveKey(password, saltB64)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("data too short")
	}

	nonce, cipherText := data[:nonceSize], data[nonceSize:]
	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}
