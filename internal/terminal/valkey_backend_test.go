package terminal

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func newValkeyBackendForTest(t *testing.T) (*ValkeyBackend, context.Context) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Fatalf("close redis client: %v", err)
		}
	})
	return NewValkeyBackend(client), context.Background()
}

func TestValkeyBackend_SetGetDeleteRoundTrip(t *testing.T) {
	backend, ctx := newValkeyBackendForTest(t)

	if err := backend.Set(ctx, "session-1", []byte(`{"user_id":"u1"}`), time.Minute); err != nil {
		t.Fatalf("set: %v", err)
	}
	payload, err := backend.Get(ctx, "session-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(payload) != `{"user_id":"u1"}` {
		t.Fatalf("payload = %q", payload)
	}
	if err := backend.Delete(ctx, "session-1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := backend.Get(ctx, "session-1"); !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("get after delete error = %v, want ErrTokenNotFound", err)
	}
}

func TestValkeyBackend_GetAndDeleteIsSingleUse(t *testing.T) {
	backend, ctx := newValkeyBackendForTest(t)

	if err := backend.Set(ctx, "session-1", []byte("payload"), time.Minute); err != nil {
		t.Fatalf("set: %v", err)
	}
	payload, err := backend.GetAndDelete(ctx, "session-1")
	if err != nil {
		t.Fatalf("getdel: %v", err)
	}
	if string(payload) != "payload" {
		t.Fatalf("payload = %q", payload)
	}
	if _, err := backend.GetAndDelete(ctx, "session-1"); !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("second getdel error = %v, want ErrTokenNotFound", err)
	}
}

func TestValkeyBackend_ValkeyBundleGetAndDeleteRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping valkey-bundle integration test in short mode")
	}
	// Gracefully skip when Docker / the testcontainers provider isn't
	// available so this test doesn't fail-stop the unit-test job on
	// CI hosts that lack a healthy Docker daemon (or where docker.io
	// rate-limits the image pull). The integration suite still runs
	// this in environments that have Docker.
	testcontainers.SkipIfProviderIsNotHealthy(t)
	ctx := context.Background()
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "valkey/valkey-bundle:9.1.0",
			ExposedPorts: []string{"6379/tcp"},
			WaitingFor:   wait.ForLog("Ready to accept connections").WithStartupTimeout(30 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start valkey-bundle container: %v", err)
	}
	t.Cleanup(func() {
		termCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := container.Terminate(termCtx); err != nil {
			t.Logf("terminate valkey-bundle container: %v", err)
		}
	})
	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("container host: %v", err)
	}
	port, err := container.MappedPort(ctx, "6379")
	if err != nil {
		t.Fatalf("container port: %v", err)
	}
	client := redis.NewClient(&redis.Options{Addr: fmt.Sprintf("%s:%s", host, port.Port())})
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Fatalf("close redis client: %v", err)
		}
	})
	backend := NewValkeyBackend(client)

	if err := backend.Set(ctx, "bundle-session", []byte("payload"), time.Minute); err != nil {
		t.Fatalf("set: %v", err)
	}
	payload, err := backend.GetAndDelete(ctx, "bundle-session")
	if err != nil {
		t.Fatalf("getdel: %v", err)
	}
	if string(payload) != "payload" {
		t.Fatalf("payload = %q", payload)
	}
	if _, err := backend.Get(ctx, "bundle-session"); !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("get after getdel error = %v, want ErrTokenNotFound", err)
	}
}

func TestValkeyBackend_GetAndDeleteAllowsOnlyOneConcurrentReader(t *testing.T) {
	backend, ctx := newValkeyBackendForTest(t)

	if err := backend.Set(ctx, "session-1", []byte("payload"), time.Minute); err != nil {
		t.Fatalf("set: %v", err)
	}

	var successes int32
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			payload, err := backend.GetAndDelete(ctx, "session-1")
			if err == nil && string(payload) == "payload" {
				atomic.AddInt32(&successes, 1)
				return
			}
			if err != nil && !errors.Is(err, ErrTokenNotFound) {
				t.Errorf("unexpected getdel error: %v", err)
			}
		}()
	}
	wg.Wait()

	if successes != 1 {
		t.Fatalf("successful GetAndDelete calls = %d, want 1", successes)
	}
}
