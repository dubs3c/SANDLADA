package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dubs3c/SANDLADA/provider"
)

type Exec interface {
	ExecWithContext(ctx context.Context, runCmd string, cmd string) error
	Exec(runCmd string, cmd string) error
}

type Runner struct{}

func (r *Runner) ExecWithContext(ctx context.Context, runCmd string, cmd string) error {
	cmdArgs := strings.Split(cmd, " ")
	command := exec.CommandContext(ctx, runCmd, cmdArgs...)
	return command.Run()
}

func (r *Runner) Exec(runCmd string, cmd string) error {
	cmdArgs := strings.Split(cmd, " ")
	command := exec.Command(runCmd, cmdArgs...)
	return command.Run()
}

// MemoryProcessing Uses Volatility to extract useful information from memory dumps
func MemoryProcessing(volatilityPath string, dumpPath string, vmInfo *provider.VMInfo, exec Exec) (bool, []error) {

	if _, err := os.Stat(volatilityPath); os.IsNotExist(err) {
		return false, []error{errors.New("can't find volatility at '" + volatilityPath + "'")}
	}

	if _, err := os.Stat(dumpPath); os.IsNotExist(err) {
		return false, []error{errors.New("can't memory dump at '" + dumpPath + "'")}
	}

	if vmInfo.VolatilityProfile == "" {
		return false, []error{errors.New("no Volatility profile chosen")}
	}

	resultDir := func(s string) string { return filepath.Join(filepath.Dir(dumpPath), s+".txt") }
	var cmdErrors []error
	var modules []string
	wg := &sync.WaitGroup{}
	maxDuration := 120 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), maxDuration)
	defer cancel()

	switch vmInfo.Platform {
	case "linux":
		modules = []string{"linux_pslist", "linux_psaux", "linux_psscan", "linux_bash", "linux_netstat", "linux_lsmod"}
	case "windows":
		modules = []string{"pslist", "hivelist", "apihooks", "clipboard", "cmdline", "cmdscan", "connscan", "sockets",
			"sockscan", "dlllist", "envars", "filescan", "handles"}
	default:
		return false, []error{errors.New("Unknown platform '" + vmInfo.Platform + "'")}
	}

	for _, module := range modules {
		wg.Add(1)
		go func(module string, wg *sync.WaitGroup, errs *[]error) {
			defer wg.Done()
			c := fmt.Sprintf("%s --profile=%s -f %s %s --output-file=%s", volatilityPath, vmInfo.VolatilityProfile, dumpPath, module, resultDir(module))
			if err := exec.ExecWithContext(ctx, "python27", c); err != nil {
				m := fmt.Sprintf("Failed running memory processing module '%s' with command %s. Error: %v", module, c, err)
				*errs = append(*errs, errors.New(m))
			}
		}(module, wg, &cmdErrors)

	}

	wg.Wait()

	if len(cmdErrors) > 0 {
		return false, cmdErrors
	}

	return true, cmdErrors
}
