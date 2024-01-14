package celo

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/rrivera/celo/errors"
)

// Cipher is an abstraction of Golang's AES cipher with GCM mode.
type Cipher struct {
	// block size of the cipher's block mode.
	blockSize int
	// aead pre-configured AEAD cipher mode.
	aead cipher.AEAD
}

// NewCipher creates a pre-configured AES GCM cipher.
func NewCipher(blockSize, nonceSize int, key []byte) (*Cipher, error) {
	op := errors.Op("cipher.NewCipher")

	// AES Cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.E(errors.Cipher, op, err)
	}

	// GCM Mode that provides integrity checks (Authentication) by default.
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.E(errors.Cipher, op, err)
	}

	return &Cipher{
		blockSize: blockSize,
		aead:      aead,
	}, nil

}

// BlockSize returns block size of the cipher
func (c *Cipher) BlockSize() int {
	return c.blockSize
}

// NonceSize returns nonce size of the cipher
func (c *Cipher) NonceSize() int {
	return c.aead.NonceSize()
}

// Encrypt encrypts plaintext
// It returns nonce and ciphertext or an error
func (c *Cipher) Encrypt(plaintext, additionalData []byte) (nonce, ciphertext []byte, err error) {
	// a new Nonce will be generated on every encryption.
	nonce = make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		// return error if the readed bytes aren't enough to fill the nonce.
		return nil, nil, errors.E(errors.Encrypt, errors.Op("cipher.Encrypt"), err)
	}
	ciphertext = c.aead.Seal(nil, nonce, plaintext, additionalData)

	// return the nonce so it can be attached to the file.
	return nonce, ciphertext, nil
}

// Decrypt decrypts the ciphertext using the passed nonce.
// It returns plaintext or an error.
func (c *Cipher) Decrypt(nonce, ciphertext []byte) (plaintext []byte, err error) {
	plaintext, err = c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// Unable to decrypt or authenticate.
		return nil, errors.E(errors.Decrypt, errors.Op("cipher.Decrypt"), err)
	}
	return plaintext, nil
}
