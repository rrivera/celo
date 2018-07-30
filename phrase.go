package celo

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"syscall"

	"github.com/nullrocks/celo/errors"
	"github.com/nullrocks/celo/messages"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/ssh/terminal"
)

// ReadPhrase read phrase from Stdin without echoing it.
// It will print instructcions if true is passed.
func ReadPhrase(printLabel bool) ([]byte, error) {
	if printLabel {
		// Print Instructions
		fmt.Print(messages.PhraseRead.String() + " ")
	}

	// Securely read the phrase without printing it.
	phrase, err := terminal.ReadPassword(syscall.Stdin)
	fmt.Println() // Prevent writing in the same line as the phrase input.
	if err != nil {
		return nil, errors.E(errors.PhraseOther, errors.Op("phrase.ReadPhrase"), err)
	}

	return phrase, nil
}

// ReadAndConfirmPhrase reads the phrase and ask for confirmation with a number
// of retries. If the passed arguments for retries is 0, the number of retries
// is unlimited.
func ReadAndConfirmPhrase(retries uint32) (phrase []byte, err error) {
	op := errors.Op("phrase.ReadAndConfirmPhrase")
	var i uint32 = 1
	var first []byte

	for ; retries == 0 || i <= retries; i++ {
		// Either the number of retries has been reached or unlimited retries(0)

		first, err = ReadPhrase(true)

		if err != nil {
			// Stop inmediately if it wasn't possible to read from Stdin.
			return nil, errors.E(errors.PhraseOther, op, err)
		}
		if len(first) == 0 {
			if i < retries {
				// Empty phrases aren't allowed. Count it as a try and continue.
				fmt.Println(errors.PhraseIsEmpty.String())
				continue
			}
			// If this is the last retry, err will be returned.
			return nil, errors.E(errors.PhraseIsEmpty, op)
		}

		fmt.Print(messages.PhraseConfirm.String() + " ")
		second, err := ReadPhrase(false)
		fmt.Println() // Prevent writing in the same line as the phrase input.
		if err != nil {
			// Stop inmediately if it wasn't possible to read from Stdin.
			return nil, errors.E(errors.PhraseOther, op, err)
		}

		if bytes.Compare(first, second) == 0 {
			// Phrases match, break the iteration and return phrase.
			return first, nil
		} else if i < retries {
			// Phrases don't match, count it as a try and continue.
			fmt.Println(errors.PhraseMismatch.String())
		}

		// Maximum allowed retries reached and still mismatch.
		return nil, errors.E(errors.PhraseMismatch, op)
	}

	return nil, errors.E(errors.PhraseMismatch, op)
}

// NewSalt generates a random salt.
// It returns the salt and number of bytes readed.
// It returns an error if it fails to read saltSize bytes.
func NewSalt(saltSize int) (salt []byte, n int, err error) {
	salt = make([]byte, saltSize)
	n, err = io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, n, errors.E(errors.Salt, errors.Op("phrase.NewSalt"), err)
	}
	return salt, n, nil
}

// GenerateKey generates a derived key of size blockSize using a phrase and a
// salt.
// It uses argon2 key derivation algorithm.
func GenerateKey(phrase, salt []byte, blockSize uint32) []byte {
	return argon2.IDKey(phrase, salt, 1, 64*1024, 4, blockSize)
}
