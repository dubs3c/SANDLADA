package server

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/dubs3c/SANDLADA/provider"
	"github.com/google/uuid"
	"gopkg.in/ini.v1"
)

// Options options for server mode
type Options struct {
	AgentVM          string
	AgentIP          string
	Config           string
	Database         string
	LocalPort        int
	Result           string
	Sample           string
	Executor         string
	VMInfo           []provider.VMInfo
	AnalysisFinished chan string
	FileWriter       FileOps
}

// Can be further developed for the interactive version
func scanner() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		fmt.Println(scanner.Text())
	}
}

func startVM(vm *provider.VMInfo) error {
	running, err := vm.IsRunning()

	if err != nil {
		log.Printf("Could not check if VM is running, error: %v\nChecking if I can contact agent...", err)

		if ok, err := IsAlive(vm.IP); err == nil {

			if ok {
				log.Println("Agent is responding to health checks, continuing...")
			} else {
				return errors.New("agent did not respond with 200 OK")
			}

		} else {
			return err
		}
	}

	if !running {
		log.Println("Starting VM...")
		if err := vm.Start(); err != nil {
			log.Fatal("Could not start VM: ", err)
			m := fmt.Sprintf("Could not start VM: %v", err)
			return errors.New(m)
		}

		log.Print("Started...\nWaiting for contact with agent...")

		for {
			ok, _ := IsAlive(vm.IP)
			if ok {
				log.Println("Agent online!")
				break
			}
			time.Sleep(3 * time.Second)
		}
	}

	return nil
}

func checkWithVirusTotal(opts *Options, virusTotalAPIKey string, projectUUID string) error {
	if virusTotalAPIKey != "" {
		var (
			hash string
			err  error
		)

		if hash, err = CalculateSHA256OfFile(opts.FileWriter, opts.Sample); err != nil {
			return err
		}

		resp, err := VirusTotalLookUpHash(hash, virusTotalAPIKey)

		if err != nil {
			return err
		}

		dest := opts.Result + "/" + projectUUID
		filename := "virustotal.txt"

		if err := WriteFileToDisk(opts.FileWriter, dest, filename, &resp); err != nil {
			return err
		}

	} else {
		return errors.New("virustotal API key empty")
	}

	return nil
}

// isAnalysisDone Analysis is finished, gracefully shutdown server
// But attempt to acquire a memory dump first
func isAnalysisDone(opts *Options, HTTPServer *http.Server, idleConnsClosed chan struct{}, vmInfo *[]provider.VMInfo, projectUUID string) error {
	requestIP := <-opts.AnalysisFinished
	if err := ShutdownHTTPServer(HTTPServer); err != nil {
		log.Println("Failed shutting down HTTP server, error: ", err)
	}
	close(idleConnsClosed)

	vm, err := FilterVM(vmInfo, requestIP)

	if err != nil {
		log.Printf("Did not find VM with IP %s", requestIP)
		return err
	}

	log.Printf("Acquiring memory capture of %s\n", vm.Name)

	if err = acquireMemoryDump(opts, &vm, projectUUID); err != nil {
		log.Printf("Memory acquisition failed, error: %v\n", err)
	}

	if err := ShutdownVm(&vm); err != nil {
		log.Printf("Failed shutting down VM '%s', error: %v", vm.Name, err)
		return err
	}

	log.Printf("Virtual machine '%s' has been reverted to previous snapshot\n", vm.Name)
	return nil
}

func acquireMemoryDump(opts *Options, vm *provider.VMInfo, projectUUID string) error {
	dest := opts.Result + "/" + projectUUID
	err := opts.FileWriter.MkdirAll(dest, os.ModeDir)

	if err != nil {
		return err
	}

	if err := vm.MemoryDump(dest); err != nil {
		return fmt.Errorf("failed acquiring memory dump of %s, error: %v", vm.Name, err)
	}

	return nil
}

// StartServer starts SANDLÅDA in server mode
func StartServer(opts Options) {

	cfg, err := ini.Load(opts.Config)
	if err != nil {
		log.Fatal("Fail to read configuration file: ", err)
	}

	// Generate UUID for sample for unique identification
	projectUUID := uuid.New().String()
	//vmProvider := cfg.Section("sandlada").Key("provider").String()
	volatilityPath := cfg.Section("sandlada").Key("volatility").String()
	virusTotalAPIKey := cfg.Section("sandlada").Key("virustotal").String()
	agentVmIP := cfg.Section(opts.AgentVM).Key("ip").String()
	idleConnsClosed := make(chan struct{})

	vmInfo := &provider.VMInfo{
		UUID:              cfg.Section(opts.AgentVM).Key("uuid").String(),
		Name:              opts.AgentVM,
		Path:              cfg.Section("virtualbox").Key("path").String(),
		Snapshot:          cfg.Section(opts.AgentVM).Key("snapshot").String(),
		IP:                cfg.Section(opts.AgentVM).Key("ip").String(),
		Platform:          cfg.Section(opts.AgentVM).Key("platform").String(),
		VolatilityProfile: cfg.Section(opts.AgentVM).Key("volatilityProfile").String(),
	}

	opts.VMInfo = append(opts.VMInfo, *vmInfo)
	opts.AnalysisFinished = make(chan string, 1)
	opts.FileWriter = &MyFileWriter{}
	runner := &Runner{}
	HTTPServer := HttpServer(opts)

	if err = startVM(vmInfo); err != nil {
		log.Fatal("Something went wrong communicating with VMs and/or agents, error: ", err)
	}

	log.Println("Sending malware sample...")

	statusCode, err := TransferFile(agentVmIP, opts.Sample)
	if err != nil {
		log.Fatalf("Could not transfer malware sample. Got status code %d, expected 200. %v", statusCode, err)
	}

	if statusCode != 200 {
		log.Fatal("Malware sample was not received correctly...")
	}

	log.Println("Malware sample received...")

	addr := fmt.Sprintf("http://%s/start?executor=%s&uuid=%s", vmInfo.IP, opts.Executor, projectUUID)
	status, err := GetRequest(addr, map[string]string{}, &[]byte{})

	if err != nil {
		log.Fatalf("Could not send HTTP request to agent, error: %v", err)
	}

	if status != 200 {
		log.Fatalf("Agent did not respond with HTTP 200, could not start analysis automatically. Error: %v", err)
	}

	if err = checkWithVirusTotal(&opts, virusTotalAPIKey, projectUUID); err != nil {
		log.Println("Virustotal check failed, error: ", err)
	}

	go func(HTTPServer *http.Server, idleConnsClosed chan struct{}) {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt)
		<-sigint
		log.Println("CTRL+C detected, shutting down")
		ShutdownHTTPServer(HTTPServer)
		close(idleConnsClosed)
	}(HTTPServer, idleConnsClosed)

	go isAnalysisDone(&opts, HTTPServer, idleConnsClosed, &opts.VMInfo, projectUUID)

	go func() {
		log.Println("Starting collection server...")
		if err := HTTPServer.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("HTTP server ListenAndServe: %v", err)
		}
	}()

	<-idleConnsClosed

	log.Println("HTTP Server done, running processing modules")

	dumpPath := opts.Result + "/" + projectUUID + "/memory.cap"
	if ok, err := MemoryProcessing(volatilityPath, dumpPath, vmInfo, runner); !ok {
		log.Println("Memory processing failed with errors: ", err)
	}

	log.Println("Analysis and processing complete!")
}
