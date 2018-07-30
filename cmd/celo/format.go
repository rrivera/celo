package main

import (
	"bytes"
	"fmt"
)

func formatGlobMatches(matches []string) string {
	totalMatches := fmt.Sprintf("%d file(s) matching criteria\n", len(matches))
	if len(matches) == 0 {
		return totalMatches
	}

	b := new(bytes.Buffer)
	b.WriteString(totalMatches)

	for _, m := range matches {
		b.WriteString("  " + m + "\n")
	}

	return b.String()
}

func formatEncryptedFiles(encrypted []string, errors []error) string {
	success := len(encrypted)
	failed := len(errors)
	summary := fmt.Sprintf("%d file(s) encrypted. (%d failed)\n", success, failed)

	if success == 0 {
		return summary
	}

	b := new(bytes.Buffer)
	b.WriteString(summary)
	b.WriteString("\nEncrypted Files:\n")

	for _, e := range encrypted {
		b.WriteString("  " + e + "\n")
	}

	return b.String()
}

func formatDecryptedFiles(encrypted []string, errors []error) string {
	success := len(encrypted)
	failed := len(errors)
	summary := fmt.Sprintf("%d file(s) decrypted. (%d failed)\n", success, failed)

	if success == 0 {
		return summary
	}

	b := new(bytes.Buffer)
	b.WriteString(summary)
	b.WriteString("\nDecrypted Files:\n")

	for _, e := range encrypted {
		b.WriteString("  " + e + "\n")
	}

	return b.String()
}
