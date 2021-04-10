package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type Writer interface {
	WriteFile(filename string, data []byte, perm os.FileMode) error
	MkdirAll(dir string, perm os.FileMode) error
}

type MyFileWriter struct{}

func (f *MyFileWriter) WriteFile(filename string, data []byte, perm os.FileMode) error {
	return ioutil.WriteFile(filename, data, perm)
}

func (f *MyFileWriter) MkdirAll(dir string, perm os.FileMode) error {
	return os.MkdirAll(dir, perm)
}

// writeFileToDisk Writes files sent for collection to disk
func WriteFileToDisk(w Writer, dir string, filename string, data *[]byte) error {
	path := dir + "/" + filename

	if err := w.MkdirAll(dir, os.ModeDir); err != nil {
		return err
	}

	if err := w.WriteFile(path, *data, 0755); err != nil {
		return err
	}

	return nil
}

func CalculateSHA256(filepath string) (string, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	encodedStr := hex.EncodeToString(h.Sum(nil))

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

func VirusTotalLookUpHash(hash string, apiKey string) ([]byte, error) {
	headers := map[string]string{}
	headers["x-apikey"] = apiKey
	resp, err := VirusTotalAPIRequest("https://www.virustotal.com/api/v3/files/"+hash, headers)

	if err != nil {
		return []byte{}, err
	}

	return resp, err
}

func (o *Options) ShutdownVm(requestIP string) {
	log.Println("Shutting down VMs")
	found := false
	for _, vm := range o.VMInfo {
		if strings.Split(vm.IP, ":")[0] == requestIP {
			found = true
			if err := vm.Stop(); err != nil {
				log.Println("Could not stop VM, error:", err)
				break
			}

			if err := vm.Revert(); err != nil {
				log.Println("Could not revert VM to latest snapshot, error:", err)
				break
			}

			log.Printf("Virtual machine '%s' has been reverted to previous snapshot\n", vm.Name)
			break
		}
	}

	if !found {
		log.Printf("IP %s was not found. Can not revert VM...", requestIP)
	}
}
