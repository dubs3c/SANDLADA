package server

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/dubs3c/SANDLADA/provider"
)

type FileOps interface {
	Write(filename string, data []byte, perm os.FileMode) error
	MkdirAll(dir string, perm os.FileMode) error
	Read(filename string) (*[]byte, error)
}

type MyFileWriter struct{}

func (f *MyFileWriter) Write(filename string, data []byte, perm os.FileMode) error {
	return ioutil.WriteFile(filename, data, perm)
}

func (f *MyFileWriter) MkdirAll(dir string, perm os.FileMode) error {
	return os.MkdirAll(dir, perm)
}

func (f *MyFileWriter) Read(filepath string) (*[]byte, error) {
	b, err := ioutil.ReadFile(filepath)
	return &b, err
}

// writeFileToDisk Writes files sent for collection to disk
func WriteFileToDisk(w FileOps, dir string, filename string, data *[]byte) error {
	path := dir + "/" + filename

	if err := w.MkdirAll(dir, os.ModeDir); err != nil {
		return err
	}

	if err := w.Write(path, *data, 0755); err != nil {
		return err
	}

	return nil
}

func CalculateSHA256OfFile(w FileOps, filepath string) (string, error) {
	contents, err := w.Read(filepath)

	hash := sha256.Sum256(*contents)

	encodedStr := hex.EncodeToString(hash[:])

	return encodedStr, err
}

// VirusTotalLookUpHash Given a hash, check if it exists in VirusTotal
func VirusTotalLookUpHash(hash string, apiKey string) ([]byte, error) {
	var body []byte
	headers := map[string]string{}
	headers["x-apikey"] = apiKey
	code, err := GetRequest("https://www.virustotal.com/api/v3/files/"+hash, headers, &body)

	if err != nil {
		return []byte{}, err
	}

	if code != 200 {
		return []byte{}, errors.New("VirusTotal did not find anything with that hash")
	}

	return body, err
}

// FilterVM Simply returns a VMInfo struct if its IP matches the requestIP
func FilterVM(vms *[]provider.VMInfo, requestIP string) (provider.VMInfo, error) {
	for _, v := range *vms {
		if strings.HasPrefix(v.IP, requestIP) {
			return v, nil
		}
	}
	return provider.VMInfo{}, errors.New("VM not found")
}

// ShutdownVm Shuts down a given VM and reverts to current snapshot
func ShutdownVm(vm provider.Machine) error {
	log.Println("Shutting down VMs")

	if err := vm.Stop(); err != nil {
		return fmt.Errorf("could not stop VM, error: %v", err)
	}

	if err := vm.Revert(); err != nil {
		return fmt.Errorf("could not revert VM to latest snapshot, error: %v", err)
	}

	return nil
}
