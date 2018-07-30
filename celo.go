package celo

import (
	"os"
	"strings"
)

// Default Celo configuration values.
const (
	// Aes256BlockSize block size used as the default value for the Celo cipher.
	// Celo uses AES GCM with a block siz of 32 (256 bits).
	Aes256BlockSize = 32

	// SaltSize arbitrary salt length used to generate cipher's keys from a
	// phrase. Celo uses argon2 key derivation to generate the key.
	SaltSize = 32

	// NonceSize nonce size recommended for encrypting and signing values with
	// AES GCM.
	NonceSize = 12

	// Extension extension used when creating encrypted files by Celo.
	//  - secrets.txt -> secrets.txt.celo
	Extension = "celo"

	// Version current version of Celo. Version value will be attached to the
	// file signature if a file is created. (See Encrypter.Encode).
	Version = 1
)

// Supported versions.
const (
	// MinVersion minimum encrypted file version supported by the decoder of the
	// running version of Celo.
	MinVersion byte = 1
	// MaxVersion maximum encrypted file version supported by the decoder of the
	// running version of Celo.
	MaxVersion byte = 1
)

// option type for a functional configuration approach.
type option func(*celo) error

// SetExtension replaces the default extension attached to encrypted files.
func SetExtension(ext string) option {
	return func(c *celo) error {
		c.ext = ext
		return nil
	}
}

// celo base struct that contains principal components to the functionality of
// celo. This is later extended by Encrypter and Decrypter.
type celo struct {
	// metadata is the File Signature or Magic Bytes encoded in an encrypted
	// file created by celo.
	metadata *Metadata

	// Cipher and Key generation configuration.
	blockSize int
	saltSize  int
	nonceSize int

	// Values used by the cipher and the key generation algorithm.
	salt       []byte
	nonce      []byte
	ciphertext []byte

	// cipher is a cipher that can be (not necessarily) used to encrypt multiple
	// files with the same key.
	cipher *Cipher

	// ext is the extension to be attached to encrypted files.
	ext string

	// preserveKey flag that indicates if the the key will be reused for to
	// encrypt / decrypt multiple files.
	preserveKey bool

	// flag that states whether the instance has been initialized and it is ready
	// to to use Encrypter.Encrypt and Decrypter.Decrypt.
	initialized bool
}

// Nonce nonce used at encryption.
func (c *celo) Nonce() []byte {
	return c.nonce
}

// SaltSize nonce size (number of bytes).
func (c *celo) NonceSize() int {
	return c.nonceSize
}

// BlockSize block size used by the cipher.
func (c *celo) BlockSize() int {
	return c.blockSize
}

// Salt salt used to generate key.
func (c *celo) Salt() []byte {
	return c.salt
}

// SaltSize salt size (number of bytes).
func (c *celo) SaltSize() int {
	return c.saltSize
}

// IsReady the celo instance has been initialized.
func (c *celo) IsReady() bool {
	return c.initialized
}

// Wipe dereference stored values.
// It sets the instance as not initialized. (Not ready).
func (c *celo) Wipe() {
	c.nonce = nil
	c.ciphertext = nil

	// A new salt will be generated if the same instance requires it. This means
	// that the generated key will be totally different.
	c.salt = nil
	// Since salt will change, cipher is no longer valid.
	c.cipher = nil

	// Mark the celo instance as not initialized so that values are regenerated.
	c.initialized = false
}

// GetEncryptedFileName returns the potential file name after being encrypted.
func (c *celo) GetEncryptedFileName(f *os.File) string {
	if c.ext == "" {
		// No extension, return the original file name.
		return f.Name()
	}

	ext := c.ext

	// Makre sure that a point is always present.
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}

	return f.Name() + ext
}

// GetDecryptedFileName returns the potential file name after being decrypted.
func (c *celo) GetDecryptedFileName(f *os.File) string {
	if c.ext == "" {
		// No extension, return the original file name.
		return f.Name()
	}

	ext := c.ext

	// Makre sure that a point is always present.
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}

	name := f.Name()

	if strings.HasSuffix(name, ext) && name != ext {
		// Remove the extension only if the file name contains it and if it does
		// not represent the whole name of the file.
		return strings.TrimSuffix(name, ext)
	}

	return name
}

// Config applies custom configurations.
func (c *celo) Config(opts ...option) {
	for _, opt := range opts {
		opt(c)
	}
}
