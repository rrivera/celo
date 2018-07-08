// Copyright (c) 2016 The Upspin Authors. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// Copyright 2018 The Celo Authors. All rights reserved.

package errors

import (
	"bytes"
	"fmt"
	"log"
	"runtime"
)

// Error is the type that implements the error interface. It contains a number
// of fields, each of different type. An Error value may leave some values unset.
type Error struct {
	// Entity is the file name or entity being processed.
	Entity Entity
	// Op is the operation being performed, usually the method being invoked
	// (Decode, Encode, Encrypt, Decrypt etc.).
	Op Op
	// Kind is the class of error, such as permission failure.
	Kind Kind
	// Err is the underlying error that triggered this one.
	Err error
}

func (e *Error) isZero() bool {
	return e.Entity == "" && e.Op == "" && e.Kind == 0 && e.Err == nil
}

var (
	_ error = (*Error)(nil)
)

// Separator is the string used to separate nested errors. By default, to make
// errors easier on the eye, nested errors are indented on a new line.
const Separator = ":\n\t"

// Op describes an operation, usually as the package and method, such as
// "Decode", "Decrypt", "DecryptFile", etc.
type Op string

// Entity is the file name or entity being processed.
type Entity string

// Kind defines the kind of error this is.
type Kind uint16

// Kinds of errors.
//
// Do not reorder this list or remove any items since that will change their
// values. New items must be added only to the end.
const (
	Other          Kind = iota // Unclassified error.
	Invalid                    // Invalid operation.
	PhraseIsEmpty              // Phrase is empty.
	PhraseMismatch             // Phrase and confirmation mismatch.
	PhraseOther                // Unable to read phrase from stdin.
	Permissions                // File required permissions are missing.
	Create                     // File couldn't be created.
	Open                       // File couldn't be opened.
	Exist                      // File already exist.
	NotExist                   // File doesn't exist.
	IsDir                      // Item is a directory.
	Pattern                    // Invalid Glob Pattern
	Signature                  // Signature mismatch
	Metadata                   // Metadata's format is invalid.
	NotReady                   // Cipher hasn't been intialized.
	BlockSize                  // Block Size is invalid.
	Nonce                      // Nonce is empty or invalid
	NonceSize                  // Nonce Size is not compatible.
	Salt                       // Salt is empty or invalid.
	SaltSize                   // Salt Size is not compatible.
	Ciphertext                 // Ciphertext is invalid
	Cipher                     // Cipher wasn't created.
	Plaintext                  // Plaintext is invalid
	Encode                     // Encoding failed.
	Decode                     // Decoding failed.
	Incompatible               // Unsupported version.
	Decrypt                    // Item already exists.
	Encrypt                    // Item does not exist.
	Internal                   // Internal error or inconsistency.
)

var Messages map[Kind]string = map[Kind]string{
	Other:          "Unknown error",
	Invalid:        "Invalid operation",
	PhraseIsEmpty:  "Empty phrase is not allowed",
	PhraseMismatch: "Phrases don't match",
	PhraseOther:    "Unable to get phrase",
	Permissions:    "Insufficient permissions",
	Create:         "File couldn't be created",
	Open:           "File couldn't be opened",
	Exist:          "File already exist",
	NotExist:       "File doesn't exist",
	IsDir:          "Directories are not supported",
	Pattern:        "Invalid Glob Pattern",
	Signature:      "File Signature is invalid",
	Metadata:       "Metadata is invalid",
	NotReady:       "Instance hasn't been initialized",
	BlockSize:      "Block Size is invalid",
	Nonce:          "Nonce is empty or invalid",
	NonceSize:      "Nonce Size is invalid",
	Salt:           "Salt is empty or invalid",
	SaltSize:       "Salt Size is invalid",
	Ciphertext:     "Ciphertext is invalid or corrupt",
	Cipher:         "Cipher couldn't be created",
	Plaintext:      "Plaintext is invalid or corrupt",
	Encode:         "Unable to Encode content",
	Decode:         "Unable to Decode content",
	Incompatible:   "Incompatible version",
	Decrypt:        "Unable to Decrypt content",
	Encrypt:        "Unable to Encrypt content",
	Internal:       "Internal error",
}

func (k Kind) String() string {
	m, ok := Messages[k]

	if !ok {
		return Messages[Other]
	}

	return m
}

// E builds an error value from its arguments. There must be at least one
// argument or E panics. The type of each argument determines its meaning.
// If more than one argument of a given type is presented, only the last one is
// recorded.
//
// The types are:
//	errors.Entity
//		The file name or entity being processed.
//	errors.Op
//		The operation being performed, usually the method being invoked (Decode,
//		Encode, Encrypt, Decrypt etc.).
//	errors.Kind
//		The class of error, such as permission failure.
//	error
//		The underlying error that triggered this one.
//
// If the error is printed, only those items that have been set to non-zero
// values will appear in the result.
//
// If Kind is not specified or Other, we set it to the Kind of the underlying
// error.
func E(args ...interface{}) error {
	if len(args) == 0 {
		panic("call to errors.E with no arguments")
	}
	e := &Error{}
	for _, arg := range args {
		switch arg := arg.(type) {
		case Entity:
			e.Entity = arg
		case Op:
			e.Op = arg
		case Kind:
			e.Kind = arg
		case *Error:
			// Make a copy
			copy := *arg
			e.Err = &copy
		case error:
			e.Err = arg
		default:
			_, file, line, _ := runtime.Caller(1)
			log.Printf("errors.E: bad call from %s:%d: %v", file, line, args)
			return Errorf("unknown type %T, value %v in error call", arg, arg)
		}
	}

	prev, ok := e.Err.(*Error)
	if !ok {
		return e
	}

	// The previous error was also one of ours. Suppress duplications so the
	// message won't contain the same kind, file name or user name twice.
	if prev.Entity == e.Entity {
		prev.Entity = ""
	}
	if prev.Kind == e.Kind {
		prev.Kind = Other
	}
	// If this error has Kind unset or Other, pull up the inner one.
	if e.Kind == Other {
		e.Kind = prev.Kind
		prev.Kind = Other
	}
	return e
}

// errorString is a trivial implementation of error.
type errorString struct {
	s string
}

func (e *errorString) Error() string {
	return e.s
}

// Errorf is equivalent to fmt.Errorf, but allows clients to import only this
// package for all error handling.
func Errorf(format string, args ...interface{}) error {
	return &errorString{fmt.Sprintf(format, args...)}
}

// pad appends str to the buffer if the buffer already has some data.
func pad(b *bytes.Buffer, str string) {
	if b.Len() == 0 {
		return
	}
	b.WriteString(str)
}

func (e *Error) Error() string {
	b := new(bytes.Buffer)

	if e.Op != "" {
		pad(b, ": ")
		b.WriteString(string(e.Op))
	}
	if e.Entity != "" {
		pad(b, ": ")
		b.WriteString(string(e.Entity))
	}
	if e.Kind != 0 {
		pad(b, ": ")
		b.WriteString(e.Kind.String())
	}
	if e.Err != nil {
		// Indent on new line if we are cascading non-empty Celo errors.
		if prevErr, ok := e.Err.(*Error); ok {
			if !prevErr.isZero() {
				pad(b, Separator)
				b.WriteString(e.Err.Error())
			}
		} else {
			pad(b, ": ")
			b.WriteString(e.Err.Error())
		}
	}
	if b.Len() == 0 {
		return "no error"
	}
	return b.String()
}

// Match compares its two error arguments. It can be used to check for expected
// errors in tests. Both arguments must have underlying type *Error or Match
// will return false. Otherwise it returns true iff every non-zero element of
// the first error is equal to the corresponding element of the second.
// If the Err field is a *Error, Match recurs on that field; otherwise it
// compares the strings returned by the Error methods.
// Elements that are in the second argument but not present in the first are
// ignored.
//
// For example,
//	Match(errors.E(errors.Entity("secrets.json"), errors.Encrypt), err)
// tests whether err is an Error with Kind=Encrypt and Entity=secrets.json.
func Match(err1, err2 error) bool {
	e1, ok := err1.(*Error)
	if !ok {
		return false
	}
	e2, ok := err2.(*Error)
	if !ok {
		return false
	}
	if e1.Entity != "" && e2.Entity != e1.Entity {
		return false
	}
	if e1.Op != "" && e2.Op != e1.Op {
		return false
	}
	if e1.Kind != Other && e2.Kind != e1.Kind {
		return false
	}
	if e1.Err != nil {
		if _, ok := e1.Err.(*Error); ok {
			return Match(e1.Err, e2.Err)
		}
		if e2.Err == nil || e2.Err.Error() != e1.Err.Error() {
			return false
		}
	}
	return true
}

// Is reports whether err is an *Error of the given Kind.
// If err is nil then Is returns false.
func Is(kind Kind, err error) bool {
	e, ok := err.(*Error)
	if !ok {
		return false
	}
	if e.Kind != Other {
		return e.Kind == kind
	}
	if e.Err != nil {
		return Is(kind, e.Err)
	}
	return false
}
