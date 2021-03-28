package agent

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
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
func (c *Collection) SendData(content []byte, filename string) (int, error) {
	reader := bytes.NewReader(content)
	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)
	part, _ := w.CreateFormFile("file", filename)
	io.Copy(part, reader)
	w.Close()
	r, err := http.NewRequest("POST", c.Server+"/collection/"+c.UUID.String(), body)
	if err != nil {
		log.Println("Error creating collection request, error:", err)
		return 0, err
	}
	r.Header.Add("Content-Type", w.FormDataContentType())
	client := &http.Client{
		Timeout: 3 * time.Second,
	}
	resp, err := client.Do(r)
	if err != nil {
		return 0, err
	}
	return resp.StatusCode, err
}

// StaticAnalysis Performs static analysis on the malware sample
func (c *Collection) StaticAnalysis(ctx context.Context) {
	log.Println("Running static analysis")
	// yara
	// objdump if linux
	// readelf if linux
	log.Println("static analysis complete")
}

// BeginNetworkSniffing Runs packet capturing
func (c *Collection) BeginNetworkSniffing(ctx context.Context) {
	log.Println("Running packet sniffing...")
	command := []string{"tcpdump", "-s", "65535", "-w", "/tmp/capture.pcap"}
	err, output := c.runCommand(ctx, "Network Sniffing", command)
	if err != nil {
		log.Println(output)
		log.Println(err)
	} else {
		log.Printf("Network sniffing finished successfully")
	}
}

func (c *Collection) runCommand(ctx context.Context, taskName string, commando []string) (error, []byte) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "sudo", commando...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := c.SendStatus(taskName+" started", nil); err != nil {
		log.Println("Could not send status that behavior analysis started, error: ", err)
	}

	err := cmd.Start()

	if err != nil {
		if err = c.SendStatus(taskName+" could not be started", err); err != nil {
			log.Println(taskName+"did not start, sending status failed with error: ", err)
		}
		log.Println("Could not start command, error: ", err)
		log.Println(stderr.String())
		return err, stderr.Bytes()
	}

	log.Printf("Waiting for %s to finish...\n", taskName)
	err = cmd.Wait()

	if err != nil {
		if err = c.SendStatus(taskName+" did not exit correctly", err); err != nil {
			log.Println(taskName+" did not exit correctly, sending status failed with error: ", err)
		}
		log.Println(taskName+" did not exit correctly, error: ", err)
		log.Println(stderr.String())
		return err, stderr.Bytes()
	}

	if err = c.SendStatus(taskName+" completed", err); err != nil {
		log.Println(taskName+" completed, sending status failed with error: ", err)
	}

	return nil, stdout.Bytes()
}

// BehaviorAnalysis Runs malware sample
// Executer specifies if the sample should be run by a specific program
// For example, some samples needs to be run as 'python2 sample.py'.
// If executer is not specified, the analysis will assume it should be executed with dot forward slash, i.e './'
func (c *Collection) BehaviorAnalysis(ctx context.Context, executer string) {
	var commando string

	if _, err := os.Stat("/tmp/binary"); os.IsNotExist(err) {
		log.Println("Malware sample does not exist")
		if err = c.SendStatus("Malware sample does not exist at /tmp/binary", err); err != nil {
			log.Println("Malware sample does not exist, sending status failed with error: ", err)
		}
		return
	}

	if len(executer) > 0 {
		commando = fmt.Sprintf("%s /tmp/binary", executer)
	} else {
		commando = fmt.Sprintf("./tmp/binary")
	}

	command := []string{"staprun", "-R", "-c", commando, "/opt/sandlada.ko"}
	err, output := c.runCommand(ctx, "Behavior Analysis", command)
	if err != nil {
		log.Println("Behavior Analysis failed, error: ", err)
		log.Println("STDOUT: ", output)
	} else {
		log.Printf("Behavior Analysis finished successfully")
	}

	if err := ioutil.WriteFile("/tmp/behave.txt", output, 0644); err != nil {
		log.Println("Could not write file, error: ", err)
	}

}
