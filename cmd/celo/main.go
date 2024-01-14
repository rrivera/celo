package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/rrivera/celo/errors"
)

const intro = `
The celo command provides file Encryption and Decryption operations through an user-defined Secret Phrase. 
It can be used to encrypt or decrypt one or multiple files at once.

  celo [COMMAND] <FILE|PATTERN> [ARG...]

  Commands:

  e (shorthand)
  encrypt <FILE|PATTERN> [ARG...]
	Encrypts file(s) using a Secret Phrase. 
	A phrase will be asked (from Stdin) unless -phrase-env flag is present.

  d (shorthand)
  decrypt <FILE|PATTERN> [ARG...]
	Decrypts file(s) using the exact same Secret Phrase used to encrypt. 
	A phrase will be asked (from Stdin) unless -phrase-env flag is present.

  --

  If COMMAND is not provided, "encrypt" will be assumed.

  For a list of available flags, run
	celo COMMAND -help
`

// flag values used by multiple commands.
var (
	// Name of the Environment Variable that contains the phrase
	phraseEnv string
	// Remove input source file after a successful operation.
	removeSource bool
	// Overwrite the content of an existing file.
	overwrite bool
)

// default error for flags parse error
var errInvalidFlags = errors.E(errors.Errorf("Invalid Flags"))

// Flags default and usage values
const (
	removeSourceDefault = false
	removeSourceUsage   = `Remove the source file when the operation finishes successfully.
	If an error occurs the source won't be removed.`

	overwriteDefault = false
	overwriteUsage   = "Overwrite existing file if one with the same name exist."

	phraseEnvDefault = ""
	phraseEnvUsage   = `Name of the ` + "`environment variable`" + ` containing the Secret Phrase.
	If "phrase-env" flag is used, celo won't ask for the Secret Phrase.
	If the value of the variable is empty an error will be thrown.
	Ex: -phrase-env CELO_PHRASE
	`
)

func main() {
	var err error

	flag.Usage = func() {
		fmt.Print(intro)
		flag.PrintDefaults()
	}

	flag.Parse()

	cmd, src, args, err := parseArgs()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	switch cmd {
	case "decrypt":
		err = decrypt(src, args)
	case "encrypt":
		err = encrypt(src, args)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

// parseArgs extracts and validates passed values such as the source,
// subcommands and flags. It also handles command aliases.
func parseArgs() (cmd string, src []string, args []string, err error) {

	err = errors.E(
		errors.Internal,
		errors.Op("main.parseArgs"),
		errors.Errorf("Source File is required"),
	)

	// The minimum number of args required to run. If less than 2 arguments
	// are passed, means that the input source (file or glob pattern) is missing.
	if len(os.Args) < 2 {
		return "", nil, nil, err
	}

	// Normalize commands aliases.
	switch os.Args[1] {
	case "e":
		os.Args[1] = "encrypt"
	case "d":
		os.Args[1] = "decrypt"
	}

	switch os.Args[1] {
	case "decrypt":
		fallthrough
	case "encrypt":

		// Manually verify if the help flag is present. If it is, celo shouldn't
		// take any action other than showing Usage message, therefore, args are
		// passed down to the subcommand.
		if hasHelpFlag(os.Args[1:]) {
			// No error is returned.
			return os.Args[1], nil, os.Args[2:], nil
		}

		// At this point, we require at least 3 arguments considering that the
		// command was explicitly passed. The third argument is the input
		// source.
		if len(os.Args) < 3 {
			return "", nil, nil, err
		}

		// Make sure that the third parameter is not a flag.
		if isFlag(os.Args[2]) {
			// If the third argument is a flag, the input source is missing.
			return "", nil, nil, err
		}

		cmd = os.Args[1]

		files, found := extractSources(os.Args[2:])

		src = files

		// remaining arguments
		args = os.Args[2+found:]

	default:
		// encrypt command is assumed if none was explicitly passed.

		if hasHelpFlag(os.Args[1:]) {
			// Since no command was specified, show base celo usage message.
			return "", nil, os.Args[1:], nil
		}

		// The first argument has to be the input source.
		if isFlag(os.Args[1]) {
			return "", nil, nil, err
		}

		cmd = "encrypt"
		files, found := extractSources(os.Args[1:])

		src = files

		// remaining arguments
		args = os.Args[1+found:]
	}

	return cmd, src, args, nil
}

// extractSources return a list of files passed as arguments.
func extractSources(args []string) (files []string, found int) {
	files = []string{}
	for _, arg := range args {
		if isFlag(arg) {
			// stop as soon as a flag is found
			break
		}

		files = append(files, arg)
		found++
	}

	return files, found
}

func isFlag(arg string) bool {
	return strings.HasPrefix(arg, "-")
}

func hasHelpFlag(args []string) bool {
	for _, a := range args {
		if a == "-help" || a == "--help" || a == "-h" || a == "--h" {
			return true
		}
	}
	return false
}
