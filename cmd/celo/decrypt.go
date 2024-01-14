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
	decryptIntro = ``

	decryptInputDefault   = "./*.celo"
	decryptInputUsage     = "`file name or glob pattern` decrypt.\n\tIf a glob is passed, it will decrypt all files that match the pattern."
	decryptExcludeDefault = ""
	decryptExcludeUsage   = "Exclude `file name or glob pattern` from decryption.\n\tUseful when a glob is used as the source selector."
)

var (
	// Exclude file name or glob pattern.
	decryptExclude string
)

var decryptCommand = flag.NewFlagSet("decrypt", flag.ExitOnError)

func initDecryptFlags() {
	decryptCommand.StringVar(&decryptExclude, "exclude", decryptExcludeDefault, decryptExcludeUsage)
	decryptCommand.BoolVar(&removeSource, "rm-source", removeSource, removeSourceUsage)
	decryptCommand.BoolVar(&overwrite, "ow", overwriteDefault, overwriteUsage)
	decryptCommand.StringVar(&phraseEnv, "phrase-env", phraseEnvDefault, phraseEnvUsage)
}

func decrypt(src []string, args []string) (err error) {

	initDecryptFlags()
	decryptCommand.Parse(args)
	if !decryptCommand.Parsed() {
		return errInvalidFlags
	}

	var matches []string

	// Unix systems automatically convert globs in a list of files unless the
	// argument is wrapped in "". However, we still want to exclude by pattern,
	// and verify that only files are listed.
	for _, pattern := range src {
		m, err := file.Glob(pattern, decryptExclude)
		if err != nil {
			return err
		}

		if len(m) == 0 {
			continue
		}

		// concatenate matches
		matches = append(matches, m...)
	}

	// Print to Stdout the final list of files that are going to be decrypted.
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
		secret, err = celo.ReadPhrase(true)
	}
	// handle either phraseEnv or phrase read errors.
	if err != nil {
		return err
	}

	d := celo.NewDecrypter()

	if len(matches) == 1 {
		// Error handling is stricter when decrypting a single file.
		decryptedFile, err := d.DecryptFile(secret, matches[0], overwrite, removeSource)
		if err != nil {
			// If decryption fails, the error will stop execution and it will be
			// printed to Stderr with an Exit Code 1.
			return err
		}

		// Print summary only when the file was decrypted successfully.
		fmt.Fprintf(os.Stdout, formatEncryptedFiles([]string{decryptedFile}, nil))
		return nil
	}

	// When Decrypting multiple files, error handling is disabled and the
	// program will finish with Exit Code 0.
	decrypted, errs := d.DecryptMultipleFiles(secret, matches, overwrite, removeSource)
	// A summary will be printed regarding decrypting errors, however, the
	// summary string contains the number of failed decryption attempts.
	fmt.Fprintf(os.Stdout, formatDecryptedFiles(decrypted, errs))
	return nil
}
