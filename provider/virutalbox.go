package provider

import (
	"bytes"
	"os/exec"
	"strings"
)

// Machine - Interface for managing virtual machines by different providers
type Machine interface {
	Start() error
	Stop() error
	Pause() error
	Revert() error
	Info() ([]byte, error)
	IsRunning() (bool, error)
}

// VMInfo - VirtualBox provider
type VMInfo struct {
	Name              string
	UUID              string
	Path              string
	Snapshot          string
	IP                string
	State             string
	Platform          string
	VolatilityProfile string
}

// Start - Start a virtual machine
func (m *VMInfo) Start() error {
	cmd := exec.Command("VBoxManage", "startvm", m.Name, "--type", "headless")
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}

// Stop - Stop a virtual machine
func (m *VMInfo) Stop() error {
	cmd := exec.Command("VBoxManage", "controlvm", m.Name, "poweroff")
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}

// Pause - Pause a virtual machine
func (m *VMInfo) Pause() error {
	cmd := exec.Command("VBoxManage", "controlvm", m.Name, "pause")
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}

// Revert - Revert virtual machine to latest snapshot
func (m *VMInfo) Revert() error {
	cmd := exec.Command("VBoxManage", "snapshot", m.Name, "restorecurrent")
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}

// Info - Show info about virtual machine
func (m *VMInfo) Info() ([]byte, error) {
	cmd := exec.Command("VBoxManage", "showvminfo", m.Name)
	if err := cmd.Run(); err != nil {
		return []byte{}, err
	}
	out, _ := cmd.Output()
	return out, nil
}

// IsRunning - Checks if virtual machine is running
func (m *VMInfo) IsRunning() (bool, error) {
	var out bytes.Buffer

	cmd := exec.Command("VBoxManage", "list", "runningvms")
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		return false, err
	}

	if string(out.String()) != "" {
		if strings.Contains(out.String(), m.Name) {
			return true, nil
		}
	}

	return false, nil
}

// MemoryDump dumps the memory of the virtual machine
func (m *VMInfo) MemoryDump(destination string) error {

	filename := destination + "/memory.cap"
	cmd := exec.Command("VBoxManage", "debugvm", m.Name, "dumpvmcore", "--filename="+filename)

	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}

/*
	Exekvera program från host i VM: VBoxManage guestcontrol 7d473abc-0796-4186-bbc4-7144b5399daf --username vagrant --password vagrant run "/bin/ps" "aux"
	Överföra filer: VBoxManage guestcontrol 7d473abc-0796-4186-bbc4-7144b5399daf --username vagrant --password vagrant copyto config.ini /home/vagrant/works.ini
*/
