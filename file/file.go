package file

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/nullrocks/celo/errors"
)

// Create a file with the provided name, if the file exists, overwrite flag has
// to be on.
func Create(name string, overwrite bool) (f *os.File, exist bool, err error) {
	op := errors.Op("file.Create")
	fi, err := os.Stat(name)

	exist = err != nil && !os.IsNotExist(err)

	switch {
	case os.IsNotExist(err):
		// File doesn't exists, which is fine since it will be created.
	case os.IsPermission(err):
		// File exists, but isn't possible to open it due to lack of permissions.
		return nil, exist, errors.E(errors.Permissions, op, err)
	case err != nil:
		// Other errors.
		return nil, exist, errors.E(errors.Permissions, op, err)
	case fi.IsDir():
		// It is a directory. (Probrably the name ends with "/")
		return nil, exist, errors.E(errors.IsDir, op)
	case !overwrite:
		// At this point we know that the file exists, if the overwrite flag is
		// of, it's content won't be replaced.
		return nil, exist, errors.E(errors.Exist, op)
	}

	file, err := os.Create(name)
	if err != nil {
		return nil, exist, errors.E(errors.Create, op, err)
	}

	return file, exist, nil
}

// Glob returns the name of existing files matching the pattern, excluding the
// ones that match ignorePattern. It ignores directories.
//        pattern:    "./*"
//  ignorePattern:    "*.celo"
//
//  Matches every file in "./" except the ones with ".celo" extension.
// Glob return
func Glob(pattern, ignorePattern string) (filepaths []string, err error) {

	f, err := filepath.Glob(pattern)
	if err != nil {
		return f, errors.E(errors.Pattern, errors.Op("file.Glob"), err)
	}

	if ignorePattern != "" {
		f = filterFilepaths(f, skipIgnored(ignorePattern))
		f = filterFilepaths(f, isFile)
	}

	return f, nil
}

// Match reports wether name matches the shell file name pattern.
//
// When pattern contains a separator, usually "/" it behaves as an alias of
// filepath.Match.
//
//  Match("/home/nullrocks/*.txt", "/home/nullrocks/note.txt") // true, nil
//  // behaves as an alias for filepath.Match.
//
// However, when the pattern does not contains a separator, it will match over
// the actual file name without the path.
//
//  Match("*.txt", "/home/nullrocks/note.txt") // true, nil. "/home/nullrocks/note.txt" is parsed to "note.txt" in the back.
//
//  // behaves different from filepath.Match, as if it was:
//  // filepath.Match("*.txt", "note.txt")
func Match(pattern, name string) (bool, error) {

	// OS separator.
	sep := string(filepath.Separator)

	if !strings.Contains(pattern, sep) {
		// When the pattern doesn't contains a separator, it will match over the
		// actual file name without the path.
		lastSep := strings.LastIndex(name, sep)
		if lastSep >= 0 {
			// Substring name from the last instance of a separator, equivalent
			// to the filename.
			name = name[lastSep+1:]
		}
	}

	matches, err := filepath.Match(pattern, name)
	if err != nil {
		return false, errors.E(errors.Pattern, errors.Op("file.Match"), err)
	}

	return matches, nil
}

func filterFilepaths(files []string, fn func(string) bool) []string {
	matches := []string{}

	for _, f := range files {
		if fn(f) {
			matches = append(matches, f)
		}
	}

	return matches
}

func matchExprFn(pattern string) func(string) bool {
	return func(file string) bool {
		m, err := filepath.Match(pattern, file)
		return err == nil && !m
	}
}

func skipIgnored(pattern string) func(string) bool {
	return func(file string) bool {
		if matches, err := Match(pattern, file); matches || err != nil {
			return false
		}
		return true
	}
}

func isFile(file string) bool {
	fi, err := os.Stat(file)
	return err == nil && !fi.IsDir()
}
