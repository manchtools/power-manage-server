package architecture_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAbolishedArchitectureCannotReturn(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))

	for _, path := range []string{
		"cmd/gateway",
		"cmd/indexer",
		"internal/api",
		"internal/eventtypes",
		"internal/projectors",
		"internal/search",
		"internal/taskqueue",
	} {
		err := filepath.WalkDir(filepath.Join(root, path), func(found string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if !entry.IsDir() {
				t.Errorf("abolished architecture returned at %s", found)
				return fs.SkipAll
			}
			return nil
		})
		if err != nil && !os.IsNotExist(err) {
			t.Fatalf("inspect %s: %v", path, err)
		}
	}

	mod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	for _, dependency := range []string{
		"github.com/alicebob/miniredis",
		"github.com/hibiken/asynq",
		"github.com/pquerna/otp",
		"github.com/redis/go-redis",
		"modernc.org/sqlite",
	} {
		if strings.Contains(string(mod), dependency) {
			t.Errorf("abolished dependency returned: %s", dependency)
		}
	}
}
