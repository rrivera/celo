// Package celo is a tool to encrypt files from a secret phrase.
// Celo encrypts files using AES GCM block cipher that provides both privacy and
// integrity checks. The Nonce used by the cipher is re-generated for every
// encryption, meaning that no nonce is reused.
//
// Key Generation
//
// Celo uses argon2 for key generation from a phrase with a random salt on every
// encryption. Even when the same phrase is used twice or more, a different key
// is generated.
//
// Celo as library
//
// Even though Celo was originally designed to be a command line interface tool,
// it makes sense to distribute it as a library hoping it could help other
// projects with similar needs.
//
//
// Encrypting a single file
//
// The book_draft.md file will be encrypted resulting in a new file with the
// a similar name, suffixed with the .celo extension.
//
// book_draft.md.celo contains everything needed to decrypt it back, including:
//  - Metadata such as version, sizes of salt, nonce, cipher block.
//  - Salt used to generate the key.
//  - Nonce used at encryption.
//
// Example:
//   e := celo.NewEncrypter()
//
//   encryptedFileName, err := e.EncryptFile(
//   	[]byte("One must acknowledge with cryptography no amount of violence will ever solve a math problem"), // Phrase
//   	"book_draft.md",   // File to encrypt
//   	true,              // Overwrite if "book_draft.md.celo" already exists.
//     false,              // Dont't remove "book_draft.md" after successful encryption.
//   )
//
//   if err != nil {
//   	panic(err.Error())
//   }
//
//   fmt.Print(encryptedFileName) // book_draft.md.celo
//
package celo
