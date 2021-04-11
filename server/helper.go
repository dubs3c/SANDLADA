package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

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

// VirusTotalAPIRequest Check with VirusTotal
func VirusTotalAPIRequest(url string, headers map[string]string) ([]byte, error) {
	r, err := http.NewRequest("GET", url, bytes.NewBuffer([]byte{}))

	if err != nil {
		return nil, err
	}

	if len(headers) != 0 {
		for header, value := range headers {
			r.Header.Add(header, value)
		}
	}

	client := &http.Client{
		Timeout: 3 * time.Second,
	}

	resp, err := client.Do(r)

	if err != nil {
		return []byte{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return []byte{}, errors.New("VirusTotal did not find anything with that hash")
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return []byte{}, err
	}

	return bodyBytes, err
}

// VirusTotalLookUpHash Given a hash, check if it exists in VirusTotal
func VirusTotalLookUpHash(hash string, apiKey string) ([]byte, error) {
	headers := map[string]string{}
	headers["x-apikey"] = apiKey
	resp, err := VirusTotalAPIRequest("https://www.virustotal.com/api/v3/files/"+hash, headers)

	if err != nil {
		return []byte{}, err
	}

	return resp, err
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
