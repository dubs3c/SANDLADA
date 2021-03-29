package agent

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// StaticAnalysis Performs static analysis on the malware sample
func (c *Collection) StaticAnalysis(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	log.Println("Running static analysis")
	// yara

	// Commands to run, prefixed with which filetype the command expects
	var commands [][]string
	commands = append(commands, []string{"elf", "objdump -D /tmp/binary"})
	commands = append(commands, []string{"elf", "readelf -a /tmp/binary"})
	commands = append(commands, []string{"any", "strings /tmp/binary"})

	for _, cmdArray := range commands {
		fileType := cmdArray[0]
		cmd := cmdArray[1]
		if fileType == c.FileType || fileType == "any" {
			cmdSplit := strings.Split(cmd, " ")
			err, out := c.runCommand(ctx, cmdSplit[0], cmdSplit)
			if err != nil {
				log.Println("Readelf command failed, error:", err)
			} else {
				filename := fmt.Sprintf("/tmp/%s.txt", cmdSplit[0])
				if err := ioutil.WriteFile(filename, out, 0755); err != nil {
					log.Printf("Could not write output from %s to /tmp/%s.txt, error: %v", filename, filename, err)
				}
			}
		} else {
			log.Printf("Command '%s' skipped because filetype '%s' did not match binary filetype '%s'", cmd, fileType, c.FileType)
		}

	}

	log.Println("Static analysis complete")
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
func (c *Collection) BehaviorAnalysis(ctx context.Context, executer string, wg *sync.WaitGroup) {
	defer wg.Done()

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
		commando = "./tmp/binary"
	}

	command := []string{"staprun", "-R", "-c", commando, "/opt/sandlada.ko"}
	err, output := c.runCommand(ctx, "Behavior Analysis", command)
	if err != nil {
		log.Println("Behavior Analysis failed, error: ", err)
		log.Println("STDOUT: ", output)
	}

	if err := ioutil.WriteFile("/tmp/behave.txt", output, 0644); err != nil {
		log.Println("Could not write file, error: ", err)
	}

}
