package celo

import (
	"bytes"
	"io"
	"io/ioutil"
	"os"

	"github.com/nullrocks/celo/errors"
	"github.com/nullrocks/celo/file"
)

// Decrypter decodes and decrypts files or sources created by Celo.
type Decrypter struct {
	celo
}

// NewDecrypter creates a Decrypter with package's default configuration.
func NewDecrypter() *Decrypter {
	return &Decrypter{
		celo: celo{
			saltSize:  SaltSize,
			blockSize: Aes256BlockSize,
			nonceSize: NonceSize,
			ext:       Extension,
		},
	}
}

// Init initializes a Decrypter instance by specifying custom salt, phrase,
// nonce, and ciphertext values.
// It returns an error if any of the values have incorrect sizes.
func (d *Decrypter) Init(secretPhrase, salt, nonce, ciphertext []byte) error {
	op := errors.Op("decrypter.Init")

	if len(salt) != d.saltSize {
		// Verify that the provided salt matches the size of the instance.
		return errors.E(errors.SaltSize, op)
	}

	if len(nonce) != d.nonceSize {
		// Verify that the provided nonce matches the size of the instance.
		return errors.E(errors.NonceSize, op)
	}

	// Assign both salt and nonce once that the sizes were validated.
	d.salt = salt
	d.nonce = nonce

	cipher, err := NewCipher(
		d.blockSize,
		d.nonceSize,
		GenerateKey(secretPhrase, d.salt, uint32(d.blockSize)),
	)
	if err != nil {
		return err
	}

	// Assign the cipher until error check has passed.
	d.cipher = cipher

	// Store the ciphertext in the current instance so it can be decrypted.
	d.ciphertext = ciphertext

	// Mark the instance as initialized. Initialized flag will mark the instance
	// as ready for decrypting.
	d.initialized = true

	return nil

}

// initCipher creates and references an AES GCM cipher. The cipher key is
// generated from a argon2 derived key using the secret phrase passed.
func (d *Decrypter) initCipher(secretPhrase []byte) (err error) {
	cipher, err := NewCipher(
		d.blockSize,
		d.nonceSize,
		GenerateKey(secretPhrase, d.salt, uint32(d.blockSize)),
	)
	if err != nil {
		return err
	}

	// Assign the cipher until the error check has passed.
	d.cipher = cipher

	return nil
}

// Decrypt decrypts ciphertext using previously stored salt and nonce values and
// the provided phrase (that generates the AES GCM key).
//
// It returns an error if the Decrypter instance isn't initialized.
// It returns the plaintext as an array of bytes or an error if the decryption
// process failed.
func (d *Decrypter) Decrypt(secretPhrase []byte) (plaintext []byte, err error) {

	if !d.IsReady() {
		// Make sure that the Decrypter instance has been initialized.
		return nil, errors.E(errors.NotReady, errors.Op("decrypter.Decrypt"))
	}

	if d.cipher == nil {
		// Initialize cipher hasn't been initialized (referenced to instance).
		// This will generate the decryption key using the salt and the phrase.
		err = d.initCipher(secretPhrase)
		if err != nil {
			return nil, err
		}
	}

	// Decrypt the ciphertext using the previously generated Nonce.
	plaintext, err = d.cipher.Decrypt(d.nonce, d.ciphertext)
	if err != nil {
		// AES GCM failed to decrypt or validate the authenticity of the
		// decrypted message.
		return nil, err
	}

	// plaintext isn't stored in the instance to prevent leaking it anywhere.
	return plaintext, nil
}

// Decode decodes from a io.Reader everything that is neccesary to initialize a
// Decrypter instance, including metadata, salt, nonce and the ciphertext.
// It returns an error if the source is not readable or any of the values aren't
// found.
// It is an alias of Decrypter.Read
func (d *Decrypter) Decode(r io.Reader) (n int, err error) {
	return d.Read(r)
}

// Read decodes from a io.Reader everything that is neccesary to initialize a
// Decrypter instance, including metadata, salt, nonce and the ciphertext.
// It returns an error if the source is not readable or any of the values aren't
// found.
func (d *Decrypter) Read(r io.Reader) (n int, err error) {
	op := errors.Op("decrypter.Read")
	var sn, nn int

	// Get file's signature and metadata, validate that it corresponds to a file
	// encrypted and encoded by Celo.
	metadata, n, err := DecodeMetadata(r)
	if err != nil {
		// Either the signature wasn't found or the metadata such as salt, nonce
		// block sizes, or version aren't valid or compatible with this version.
		return n, err
	}

	// Reference metadata's instance until validation has passed.
	d.metadata = metadata

	salt := make([]byte, d.saltSize)
	// Salt should be part of the reader source.
	if sn, err := io.ReadFull(r, salt); err != nil {
		// Make sure that there are enough bytes to fill the desired salt size.
		return n + sn, errors.E(errors.Salt, op, err)
	}
	n += sn

	if d.salt == nil || !bytes.Equal(salt, d.salt) {
		d.salt = salt
		// Dereference cipher since the salt has changed, therefore, the key is
		// going to be different.
		d.cipher = nil
	}

	d.nonce = make([]byte, d.nonceSize)
	// Nonce should be part of the reader source.
	if nn, err := io.ReadFull(r, d.nonce); err != nil {
		// Make sure that there are enough bytes to fill the desired nonce size.
		return n + nn, errors.E(errors.Nonce, op, err)
	}
	n += nn

	// Remaining bytes correspond to the ciphertext.
	d.ciphertext, err = ioutil.ReadAll(r)
	n += len(d.ciphertext)
	if err != nil {
		return n, errors.E(errors.Ciphertext, op, err)
	}

	// Mark the instance as initialized. Initialized flag will mark the instance
	// as ready for decrypting.
	d.initialized = true

	return n, nil
}

// DecryptFile decrypts a file with the specified name. It requires the secret
// phrase.
// It returns the name of the decrypted file or an error.
// If a file with the same name as the decrypted file exists, overwrite has to
// be `true` in order to overwrite the content of the file.
func (d *Decrypter) DecryptFile(secretPhrase []byte, name string, overwrite, removeSource bool) (decryptedFileName string, err error) {
	op := errors.Op("decrypter.DecryptFile")
	encryptedFile, err := os.Open(name)
	if err != nil {
		return "", errors.E(errors.Open, op, err)
	}
	defer encryptedFile.Close()

	// Read source file, verify metadata and initialize current instance with
	// salt, nonce, ciphertext values.
	_, err = d.Read(encryptedFile)
	if err != nil {
		return "", err
	}

	// Decrypts the content of the ciphertext generating the cipher key with the
	// provided phrase.
	plaintext, err := d.Decrypt(secretPhrase)
	if err != nil {
		return "", err
	}

	// Get the decrypted file name removing the .celo extension.
	decryptedFileName = d.GetDecryptedFileName(encryptedFile)

	// file.Create handles wether the file exists and it is writable and returns
	// an os.File instance ready to write on it.
	decryptedFile, exist, err := file.Create(decryptedFileName, overwrite)
	if err != nil {
		// An error returned means that the file couldn't be created due to lack
		// of permissions or there was an existing file with the same name and
		// the overwrite flag is false, therefore, it shouldn't overwrite it's
		// content.
		return "", err
	}
	defer decryptedFile.Close()

	_, err = decryptedFile.Write(plaintext)
	if err != nil {
		if !exist {
			// Remove the file when it is not possible to write in it and it
			// didn't existed before.
			os.Remove(decryptedFile.Name())
		}
		return "", errors.E(errors.Create, op, err)
	}

	// Remove source file if the operation finishes successfully.
	if removeSource {
		os.Remove(name)
	}

	return decryptedFileName, nil
}

// DecryptMultipleFiles decrypts a list of files with the specified names.
// It requires the secret phrase.
// If a file with the same name as the decrypted file exists, overwrite has to
// be true in order to replace the content of the file.
// It returns a list of file names that were successfully decrypted and a list
// of errors, each for a file that couldn't be decrypted.
func (d *Decrypter) DecryptMultipleFiles(secretPhrase []byte, fileNames []string, overwrite, removeSource bool) (decryptedFileNames []string, errs []error) {
	errs = []error{}
	decryptedFileNames = []string{}
	for _, eFileName := range fileNames {
		decryptedName, err := d.DecryptFile(secretPhrase, eFileName, overwrite, removeSource)
		if err != nil {
			errs = append(errs, errors.E(errors.Decrypt, errors.Op("decrypter.DecryptMultipleFiles"), errors.Entity(eFileName), err))
		} else {
			decryptedFileNames = append(decryptedFileNames, decryptedName)
		}
	}
	return decryptedFileNames, errs
}
