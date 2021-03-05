package main

import (
	"os/exec"
	"strings"
)

// Machine - Interface for managing virtual machines by different providers
type Machine interface {
	Start() error
	Stop() error
	Pause() error
	Revert() error
	Status() (bool, error)
}

// VBox  - VirtualBox provider
type VBox struct {
	Name string
	UUID string
}

// Start - Start a virtual machine
func (m *VBox) Start() error {
	cmd := exec.Command("VBoxManage", "startvm", m.UUID, "--type", "headless")
	if err := command(cmd); err != nil {
		return err
	}
	return nil
}

// Stop - Stop a virtual machine
func (m *VBox) Stop() error {
	cmd := exec.Command("VBoxManage", "controlvm", m.UUID, "poweroff")
	if err := command(cmd); err != nil {
		return err
	}
	return nil
}

// Pause - Pause a virtual machine
func (m *VBox) Pause() error {
	cmd := exec.Command("VBoxManage", "controlvm", m.UUID, "pause")
	if err := command(cmd); err != nil {
		return err
	}
	return nil
}

// Revert - Revert virtual machine to latest snapshot
func (m *VBox) Revert() error {
	cmd := exec.Command("VBoxManage", "snapshot", m.UUID, "restorecurrent")
	if err := command(cmd); err != nil {
		return err
	}
	return nil
}

// Info - Show info about virtual machine
func (m *VBox) Info() error {
	cmd := exec.Command("VBoxManage", "showvminfo", m.UUID)
	if err := command(cmd); err != nil {
		return err
	}
	return nil
}

// Status - Return status of virtual machine
func (m *VBox) Status() (bool, error) {
	cmd := exec.Command("VBoxManage", "list", "runningvms")
	if err := command(cmd); err != nil {
		return false, err
	}
	out, _ := cmd.Output()
	if strings.Contains(string(out), m.UUID) {
		return true, nil
	}
	return false, nil
}

func command(e *exec.Cmd) error {
	if err := e.Run(); err != nil {
		return err
	}
	return nil
}

/*
	Exekvera program från host i VM: VBoxManage guestcontrol 7d473abc-0796-4186-bbc4-7144b5399daf --username vagrant --password vagrant run "/bin/ps" "aux"
	Överföra filer: VBoxManage guestcontrol 7d473abc-0796-4186-bbc4-7144b5399daf --username vagrant --password vagrant copyto config.ini /home/vagrant/works.ini
*/
