package server

import (
	"context"
	"testing"

	"github.com/dubs3c/SANDLADA/provider"
)

type TestRunner struct{}

func (r *TestRunner) ExecWithContext(ctx context.Context, runCmd string, cmd string) error {
	return nil
}

func (r *TestRunner) Exec(runCmd string, cmd string) error {
	return nil
}

func TestMemoryProcessing(t *testing.T) {
	mem := &provider.VMInfo{
		Platform:          "linux",
		VolatilityProfile: "CoolProfile",
	}

	_, errors := MemoryProcessing("./processing.go", "./processing.go", mem, &TestRunner{})

	if len(errors) > 0 {
		t.Errorf("expected zero errors, got %d. Errors: %s", len(errors), errors)
	}
}
