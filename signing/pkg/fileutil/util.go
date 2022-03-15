package fileutil

import (
	"path/filepath"
	"runtime"
	"strings"
)

func GetFilePathFromRepositoryRoot(relativePath string) (string, error) {
	_, filename, _, _ := runtime.Caller(0)
	curDir := filepath.Dir(filename)
	rv, err := filepath.Abs(filepath.Join(curDir, "../../..", relativePath))
	return strings.ReplaceAll(rv, `\`, `\\`), err
}
