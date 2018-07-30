package celo

import (
	"bytes"
	"io"

	"github.com/nullrocks/celo/errors"
)

// SignatureSize size of bytes used by the Celo file signature.
//  ..CELO.. 8
//  vsbn.... 8
//  ........ 8
//  ........ 8
//         = 32
const SignatureSize = 32

var signatureHeader = [8]byte{0x0A, 0x1A, 0x43, 0x45, 0x4C, 0x4F, 0x0A, 0x1A}

const (
	// versionIndex index of byte that contains the Version used to encrypt.
	versionIndex = iota
	// saltSizeIndex index of byte that contains the salt size used to generate
	// the key.
	saltSizeIndex
	// blockSizeIndex index of byte that contains the block size of the cipher.
	blockSizeIndex
	// nonceSizeIndex index of byte that contains the nonce size used by the
	// AES GCM block cipher.
	nonceSizeIndex
)

// SignatureHeader File Signature also known as Magic Bytes that identify a file
// created by Celo.
//  ..CELO.. <-- Signature Header
//  vsbn.... v = version, s = saltSize, b = blockSize, n = nonceSize
//  ........
//  ........
func SignatureHeader() [8]byte {
	var sh [8]byte
	copy(sh[:], signatureHeader[:])
	return sh
}

// Metadata stores the file signature.
type Metadata struct {
	signature [8]byte
	vsbn      [4]byte // v = version, s = saltSize, b = blockSize, n = nonceSize
	reserved  [20]byte
}

// Bytes of the File Signature that includes metadata about the encrypted file.
// This is how it should look using ISO 8859-1 encoding. "????" are placeholders
// for version, saltSize, blockSize and nonceSize bytes in that order.
//  ..CELO..
//  ????....
//  ........
//  ........
func (m *Metadata) Bytes() []byte {
	b := make([]byte, SignatureSize)
	for i := 0; i < len(m.signature); i++ {
		b[i] = m.signature[i]
	}
	b[8] = m.vsbn[versionIndex]
	b[9] = m.vsbn[saltSizeIndex]
	b[10] = m.vsbn[blockSizeIndex]
	b[11] = m.vsbn[nonceSizeIndex]

	return b
}

// Size size of the file signature.
func (m *Metadata) Size() int {
	return SignatureSize
}

// Verify compares an array of bytes to verify that they are equivalent to
// current instance of metadata.
func (m *Metadata) Verify(b []byte) bool {
	return bytes.Equal(m.Bytes(), b)
}

// DecodeMetadata tries to decode the metadata from a reader.
// It returns error if any of the values is missing or doesn't pass validations.
func DecodeMetadata(r io.Reader) (m *Metadata, n int, err error) {
	op := errors.Op("metadata.DecodeMetadata")

	// Keep track of the bytes read from the io.Reader.
	var vn, rn int

	// First 8 bytes are the signature header used to identify a file created by
	// celo.
	signature := [8]byte{}
	if n, err := io.ReadFull(r, signature[:]); err != nil {
		return nil, n, errors.E(errors.Metadata, op, err)
	}

	// Following 4 bytes contain the version, saltSize, blockSize, nonceSize in
	// that order.
	vsbn := [4]byte{}
	if vn, err := io.ReadFull(r, vsbn[:]); err != nil {
		return nil, n + vn, errors.E(errors.Metadata, op, err)
	}
	n += vn

	reserved := [20]byte{}
	if rn, err := io.ReadFull(r, reserved[:]); err != nil {
		return nil, n + rn, errors.E(errors.Metadata, op, err)
	}
	n += rn

	// Validate that all the values present and correct;
	// Version is supported by current Celo version and sizes are inside the
	// boundaries.
	if err = ValidateMetadata(signature, vsbn, reserved); err != nil {
		return nil, n, err
	}

	return &Metadata{
		signature: signature,
		vsbn:      vsbn,
		reserved:  reserved,
	}, n, nil

}

// ValidateMetadata validates correctness of the signature header, version, salt
// size, block size and nonce size.
func ValidateMetadata(signature [8]byte, vsbn [4]byte, reserved [20]byte) error {
	op := errors.Op("metadata.ValidateMetadata")

	if !bytes.Equal(signature[:], signatureHeader[:]) {
		return errors.E(errors.Signature, op)
	}

	if vsbn[versionIndex] < MinVersion || vsbn[versionIndex] > MaxVersion {
		return errors.E(errors.Incompatible, op)
	}

	if vsbn[blockSizeIndex] != 16 && vsbn[blockSizeIndex] != 32 {
		return errors.E(errors.NonceSize, op)
	}

	if vsbn[nonceSizeIndex] > 32 {
		return errors.E(errors.NonceSize, op)
	}

	// For future use. Prevent unused variable error.
	_ = reserved

	return nil
}

// newMetadata creates a Metadata if passed values are correct.
func newMetadata(version, blockSize, saltSize, nonceSize byte) (m *Metadata, err error) {
	vsbn := [4]byte{version, saltSize, blockSize, nonceSize}
	reserved := [20]byte{}

	if err = ValidateMetadata(signatureHeader, vsbn, reserved); err != nil {
		return nil, err
	}

	return &Metadata{
		signature: signatureHeader,
		vsbn:      vsbn,
		reserved:  [20]byte{},
	}, nil
}

// newCurrentMetadata creates a Metadata with the values of the current running
// version of Celo (from constants).
func newCurrentMetadata() (m *Metadata) {
	vsbn := [4]byte{byte(Version), byte(SaltSize), byte(Aes256BlockSize), byte(NonceSize)}
	return &Metadata{
		signature: signatureHeader,
		vsbn:      vsbn,
		reserved:  [20]byte{},
	}
}
