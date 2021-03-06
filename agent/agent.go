package agent

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Task contains the state of each step in the analysis flow
type Task struct {
	StaticAnalysis   string
	BehaviorAnalysis string
	NetworkSniffing  string
}

// Collection contains information about the collection server
// and the ID of a given analysis
type Collection struct {
	Server   string
	UUID     uuid.UUID
	Task     *Task
	Executer string
}

// SendStatus sends a status update to the collection server
// for a given analysis project
func (c *Collection) SendStatus(status string, statusError error) error {
	data := url.Values{}
	data.Set("message", status)
	if statusError != nil {
		data.Set("error", statusError.Error())
	} else {
		data.Set("error", "")
	}
	body := strings.NewReader(data.Encode())
	collectionServer := fmt.Sprintf("%s/status/%s", c.Server, c.UUID)
	_, err := http.Post(collectionServer, "application/x-www-form-urlencoded", body)
	return err
}

// SendData sends collected data to the collection server running on the host machine
func (c *Collection) SendData(content []byte, filename string) error {
	reader := bytes.NewReader(content)
	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)
	part, _ := w.CreateFormFile("file", filename)
	io.Copy(part, reader)
	log.Println(body)
	w.Close()
	r, err := http.NewRequest("POST", c.Server+"/collection", body)
	if err != nil {
		log.Println("Error creating collection request, error:", err)
		return err
	}
	r.Header.Add("Content-Type", w.FormDataContentType())
	client := &http.Client{
		Timeout: 3 * time.Second,
	}
	_, err = client.Do(r)
	return err
}

// StaticAnalysis Performs static analysis on the malware sample
func (c *Collection) StaticAnalysis() {
	// yara
	// objdump if linux
	// readelf if linux
	//
}

// BeginNetworkSniffing Runs packet capturing
func (c *Collection) BeginNetworkSniffing() {
	// sniff the network
}

// BehaviorAnalysis Runs malware sample
// Executer specifies if the sample should be run by a specific program
// For example, some samples needs to be run as 'python2 sample.py'.
// If executer is not specified, the analysis will assume it should be executed with dot forward slash, i.e './'
func (c *Collection) BehaviorAnalysis(executer string) {
	var commando string
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	if len(executer) > 0 {
		commando = fmt.Sprintf("%s /tmp/binary", executer)
	} else {
		commando = fmt.Sprintf("./tmp/binary")
	}

	cmd := exec.Command("sudo", "staprun", "-c", commando, "/home/vagrant/stp-scripts/sandlada.ko")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := c.SendStatus("Behavior analysis started", nil); err != nil {
		log.Println("Could not send status that behavior analysis started, error: ", err)
	}

	err := cmd.Start()

	if err != nil {
		if err = c.SendStatus("Could not start behavior analysis", err); err != nil {
			log.Println("Behavior analysis did not start, sending status failed with error: ", err)
		}
		log.Println("Could not start command, error: ", err)
		return
	}

	log.Printf("Waiting for command to finish...")
	err = cmd.Wait()

	if err != nil {
		if err = c.SendStatus("Behavior analysis did not exit correctly", err); err != nil {
			log.Println("Behavior analysis did not exit correctly, sending status failed with error: ", err)
		}
		log.Println("Behavior analysis did not exit correctly, error: ", err)
		return
	}

	if err = c.SendStatus("Behavior analysis completed", err); err != nil {
		log.Println("Behavior analysis completed, sending status failed with error: ", err)
	}

	log.Printf("Command finished successfully")

	if err = c.SendData(stdout.Bytes(), "behavior.out"); err != nil {
		log.Println("Could not send behavior analysis output to collection server, error: ", err)
		// if this happens, save to disk instead?
	}
}
