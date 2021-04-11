package server

import (
	"os"
	"reflect"
	"testing"

	"github.com/dubs3c/SANDLADA/provider"
)

type FakeFileOps struct{}

func (f *FakeFileOps) Write(filename string, data []byte, perm os.FileMode) error { return nil }
func (f *FakeFileOps) MkdirAll(dir string, perm os.FileMode) error                { return nil }

func (f *FakeFileOps) Read(filepath string) (*[]byte, error) {
	r := []byte("this is a test")
	return &r, nil
}

func TestSHA256(t *testing.T) {

	ops := &FakeFileOps{}

	hash, err := CalculateSHA256OfFile(ops, "")
	expectedHash := "2e99758548972a8e8822ad47fa1017ff72f06f3ff6a016851f45c398732bc50c"

	if err != nil {
		t.Fatal(err)
	}

	if hash != expectedHash {
		t.Errorf("SHA256 is incorrect, expected %s, got %s", hash, expectedHash)
	}
}

// Machine - Interface for managing virtual machines by different providers
type TestMachine interface {
	Start() error
	Stop() error
	Pause() error
	Revert() error
	Info() ([]byte, error)
	IsRunning() (bool, error)
}

type TestVMInfo struct {
	Name     string
	UUID     string
	Path     string
	Snapshot string
	IP       string
	State    string
}

func (m *TestVMInfo) Stop() error              { return nil }
func (m *TestVMInfo) Start() error             { return nil }
func (m *TestVMInfo) Pause() error             { return nil }
func (m *TestVMInfo) Revert() error            { return nil }
func (m *TestVMInfo) Info() ([]byte, error)    { return []byte{}, nil }
func (m *TestVMInfo) IsRunning() (bool, error) { return false, nil }

func TestShutdownVM(t *testing.T) {
	test := &TestVMInfo{
		Name: "VM 1",
		IP:   "1.1.1.1",
	}

	if err := ShutdownVm(test); err != nil {
		t.Errorf("Did not successfully stop and revert VM")
	}
}

func TestFilterVM(t *testing.T) {

	type test struct {
		ip   string
		want provider.VMInfo
	}

	infos := []provider.VMInfo{
		{
			Name: "VM 1",
			IP:   "1.1.1.1:9001",
		},
		{
			Name: "VM 2",
			IP:   "2.2.2.2:9001",
		},
	}

	tests := []test{
		{ip: "1.1.1.1", want: infos[0]},
		{ip: "2.2.2.2", want: infos[1]},
		{ip: "3.3.3.3", want: provider.VMInfo{}},
	}

	for _, tc := range tests {
		got, _ := FilterVM(&infos, tc.ip)
		if !reflect.DeepEqual(tc.want, got) {
			t.Fatalf("expected: %v, got: %v", tc.want, got)
		}
	}

}
