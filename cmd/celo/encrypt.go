package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/rrivera/celo"
	"github.com/rrivera/celo/errors"
	"github.com/rrivera/celo/file"
)

const (
	encryptIntro = ``

	encryptInputDefault   = "./*"
	encryptInputUsage     = "`file name or glob pattern` encrypt.\n\tIf a glob is passed, it will encrypt all files that match the pattern."
	encryptExcludeDefault = "*.celo"
	encryptExcludeUsage   = "Exclude `file name or glob pattern` from encryption.\n\tUseful when a glob is used as the source selector."

	noConfirmDefault = false
	noConfirmUsage   = "Skip Secret Phrase confirmation. Only ask for the Secret Phrase once."

	extensionDefault = "celo"
	extensionUsage   = "Define a custom `file extension` for encrypted files."
)

var (
	// Don't ask for phrase confirmation at encryption.
	noConfirm bool
	// Override default extension attached to encrypted files.
	extension string
	// Exclude file name or glob pattern
	encryptExclude string
)

var encryptCommand = flag.NewFlagSet("encrypt", flag.ExitOnError)

func initEncryptFlags() {
	encryptCommand.StringVar(&encryptExclude, "exclude", encryptExcludeDefault, encryptExcludeUsage)
	encryptCommand.BoolVar(&removeSource, "rm-source", removeSourceDefault, removeSourceUsage)
	encryptCommand.BoolVar(&overwrite, "ow", overwriteDefault, overwriteUsage)
	encryptCommand.StringVar(&extension, "ext", extensionDefault, extensionUsage)
	encryptCommand.StringVar(&phraseEnv, "phrase-env", phraseEnvDefault, phraseEnvUsage)
	encryptCommand.BoolVar(&noConfirm, "nc", noConfirmDefault, noConfirmUsage)
}

func encrypt(src []string, args []string) (err error) {

	initEncryptFlags()
	encryptCommand.Parse(args)
	if !encryptCommand.Parsed() {
		return errInvalidFlags
	}

	matches := []string{}

	// Unix systems automatically convert globs in a list of files unless the
	// argument is wrapped in "". However, we still want to exclude by pattern,
	// and verify that only files are listed.
	for _, pattern := range src {
		m, err := file.Glob(pattern, encryptExclude)
		if err != nil {
			return err
		}

		if len(m) == 0 {
			continue
		}

		// concatenate matches
		matches = append(matches, m...)
	}

	// Print to Stdout the final list of files that are going to be encrypted.
	fmt.Fprintln(os.Stdout, formatGlobMatches(matches))

	if len(matches) == 0 {
		return nil
	}

	var secret []byte

	if phraseEnv != "" {
		// Handle Secret Phrase stored in environment variables
		if os.Getenv(phraseEnv) != "" {
			secret = []byte(os.Getenv(phraseEnv))
		} else {
			err = errors.E(errors.Internal, errors.Errorf("Environment Variable %s is empty", phraseEnv))
		}
	} else {
		// Handle phrase read.
		// noConfirm flag decides whether to ask form phrase confirmation or not.
		if noConfirm {
			secret, err = celo.ReadPhrase(true)
		} else {
			secret, err = celo.ReadAndConfirmPhrase(3)
		}
	}
	// handle either phraseEnv or phrase read errors.
	if err != nil {
		return err
	}

	e := celo.NewEncrypter()

	if extension != "" {
		// replace default extension
		e.Config(celo.SetExtension(extension))
	}

	if len(matches) == 1 {
		// Error handling is stricter when encrypting a single file.
		encryptedFile, err := e.EncryptFile(secret, matches[0], overwrite, removeSource)
		if err != nil {
			// If encryption fails, the error will stop execution and it will be
			// printed to Stderr with an Exit Code 1.
			return err
		}

		// Print summary only when the file was encrypted successfully.
		fmt.Fprintf(os.Stdout, formatEncryptedFiles([]string{encryptedFile}, nil))
		return nil
	}

	// When Encrypting multiple files, error handling is disabled and the
	// program will finish with Exit Code 0.
	encrypted, errs := e.EncryptMultipleFiles(secret, matches, overwrite, removeSource)
	// A summary will be printed regarding encrypting errors, however, the
	// summary string contains the number of failed encryption attempts.
	fmt.Fprintf(os.Stdout, formatEncryptedFiles(encrypted, errs))

	return nil
}
