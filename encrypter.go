package celo

import (
	"io"
	"os"

	"github.com/rrivera/celo/errors"
	"github.com/rrivera/celo/file"
)

// Encrypter encrypts and encodes files and sources.
type Encrypter struct {
	celo
}

// NewEncrypter creates a Encrypter with package's default configurations.
func NewEncrypter() *Encrypter {
	return &Encrypter{
		celo: celo{
			metadata:  newCurrentMetadata(),
			saltSize:  SaltSize,
			blockSize: Aes256BlockSize,
			nonceSize: NonceSize,
			ext:       Extension,
		},
	}
}

// Init initialized an Encrypter instance by specifying a secret phrase that
// will generate a key, later used to create a cipher.
// It returns an error the cipher is not created.
// It marks the instance as initialized (Ready to encrypt).
func (e *Encrypter) Init(secretPhrase []byte) (err error) {
	if e.initialized && e.preserveKey {
		// When the instance has been initialized before AND the preserveKey
		// flag is on, there is no need to change the key, therefore, the cipher
		// instance can be re-used.
		return nil
	}

	// Mark the Encrypter as initialized.
	e.initialized = true

	// Salt should be randomized on every request unless preserveKey flag is on.
	e.salt, _, err = NewSalt(e.saltSize)
	if err != nil {
		return err
	}

	// Cipher must be re-created every time the salt changes.
	cipher, err := NewCipher(
		e.blockSize,
		e.nonceSize,
		GenerateKey(secretPhrase, e.salt, uint32(e.blockSize)),
	)
	if err != nil {
		return err
	}

	// Assign cipher once error validation has passed.
	e.cipher = cipher

	return err
}

// Encrypt encrypts plaintext using previously stored salt and nonce values and
// the provided phrase (that generates the AES GCM key).
//
// It returns the ciphertext as an array of bytes if the encryption success.
// It will initialize the instance with a new cipher.
// It returns an error if the decryption process fails.
func (e *Encrypter) Encrypt(secretPhrase []byte, plaintext []byte) (ciphertext []byte, err error) {
	// Initialize Encrypter by generating a Salt -> generate a key -> to create
	// a cipher.
	err = e.Init(secretPhrase)
	if err != nil {
		return nil, err
	}

	var nonce []byte
	nonce, e.ciphertext, err = e.cipher.Encrypt(plaintext, nil)
	if err != nil {
		// AES GCM failed to encrypt the plaintext.
		return nil, err
	}

	// Save the generated nonce to the Encrypter instance so it can be attached
	// to the file in the encoding process.
	e.nonce = nonce

	return e.ciphertext, nil
}

// Encode encodes metadata, salt, nonce and the ciphertext to an io.Writer in a
// way that it can be parsed back to a Decrypter instance.
// It returns the number of bytes written.
// It returns an error if the Encrypter is not ready (not initialized).
// It returns an error if the source is not writeable.
// It is an alias of Encrypter.Write.
func (e *Encrypter) Encode(w io.Writer) (n int, err error) {
	return e.Write(w)
}

// Write encodes metadata, salt, nonce and the ciphertext to an io.Writer in a
// way that it can be parsed back to a Decrypter instance.
// It returns the number of bytes written.
// It returns an error if the Encrypter is not ready (not initialized).
// It returns an error if the source is not writeable.
func (e *Encrypter) Write(w io.Writer) (n int, err error) {
	op := errors.Op("encrypter.Write")

	if !e.IsReady() {
		// Encrypter needs to be initialized before, which means that the salt,
		// cipher and nonce shouldn't be nil.
		return 0, errors.E(errors.NotReady, op)
	}

	// Keep track of the number of bytes written at any point.
	var sn, nn, cn int

	if sn, err := w.Write(e.metadata.Bytes()); err != nil {
		// The metadata includes File Signutere along with version and sizes
		// specified in the first 32 bytes.
		return sn, errors.E(errors.Encode, op, err)
	}

	// Salt is required to generate the key for decryption, it needs to be
	// attached to the file.
	if n, err := w.Write(e.salt); err != nil {
		return n + sn, errors.E(errors.Encode, op, err)
	}
	n += sn

	// Nonce is required to decrypt the ciphertext, it needs to be attached
	// to the file.
	if nn, err := w.Write(e.nonce); err != nil {
		return n + nn, errors.E(errors.Encode, op, err)
	}
	n += nn

	// The ciphertext is the last chunk of bytes written to the file.
	if cn, err := w.Write(e.ciphertext); err != nil {
		return n + cn, errors.E(errors.Encode, op, err)
	}

	return n + cn, nil
}

// EncryptFile encrypts a file with the specified name. It requires the secret
// phrase to generate the encryption key.
// It returns the name of the encrypted file or an error.
// If a file with the same name as the encrypted file exists, overwrite has
// to be `true` in order to overwrite the content of the file.
func (e *Encrypter) EncryptFile(secretPhrase []byte, name string, overwrite, removeSource bool) (encryptedName string, err error) {
	op := errors.Op("encrypter.EncryptFile")

	sourceFile, err := os.Open(name)
	if err != nil {
		return "", errors.E(errors.Open, op, err)
	}
	defer sourceFile.Close()

	// Read the content of the file that will be encrypted.
	plaintext, err := io.ReadAll(sourceFile)
	if err != nil {
		return "", errors.E(errors.Plaintext, op, err)
	}

	// Encrypt the file using a secret phrase to generate the encryption key.
	// Salt and Nonce will be randomly generated in the encryption process
	// unless preserveKey flag is off and they were initialized before.
	_, err = e.Encrypt(secretPhrase, plaintext)
	if err != nil {
		return "", err
	}

	// Get the encrypted file name adding the .celo extension.
	encryptedName = e.GetEncryptedFileName(sourceFile)

	// file.Create handles whether the file exists and it is writable and returns
	// an os.File instance ready to write on it.
	encryptedFile, exist, err := file.Create(encryptedName, overwrite)
	if err != nil {
		// An error returned means that the file couldn't be created due to lack
		// of permissions or there was an existing file with the same name and
		// the overwrite flag is false, therefore, it shouldn't overwrite it's
		// content.
		return "", err
	}
	defer encryptedFile.Close()

	_, err = e.Write(encryptedFile)
	if err != nil {
		if !exist {
			// Remove the file when it is not possible to write in it and it
			// didn't existed before.
			os.Remove(encryptedFile.Name())
		}
		return "", err
	}

	// Remove source file if the operation finishes successfully.
	if removeSource {
		os.Remove(name)
	}

	return encryptedName, nil
}

// EncryptMultipleFiles encrypts a list of files with the specified names.
// It requires the secret phrase.
// If a file with the same name as the encrypted file exists, overwrite has
// to be true in order to replace the content of the file.
// It returns a list of file names that were successfully encrypted and a list
// of errors, each for a file that couldn't be encrypted.
func (e *Encrypter) EncryptMultipleFiles(
	secretPhrase []byte,
	fileNames []string,
	overwrite,
	removeSource bool,
) (encryptedFileNames []string, errs []error) {
	errs = []error{}
	encryptedFileNames = []string{}
	for _, sourceFile := range fileNames {
		encryptedName, err := e.EncryptFile(secretPhrase, sourceFile, overwrite, removeSource)
		if err != nil {
			errs = append(
				errs,
				errors.E(errors.Encrypt, errors.Op("encrypter.EncryptMultipleFiles"), errors.Entity(sourceFile), err))
		} else {
			encryptedFileNames = append(encryptedFileNames, encryptedName)
		}
	}

	return encryptedFileNames, errs
}
