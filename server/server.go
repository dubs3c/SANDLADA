package server

import (
	"bufio"
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

// StartServer starts SANDLÅDA in server mode
func StartServer(opts Options) {
	var m provider.Machine
	cfg, err := ini.Load(opts.Config)
	if err != nil {
		log.Fatal("Fail to read configuration file: ", err)
	}

	// Generate UUID for sample for unique identification
	projectUUID := uuid.New().String()
	vmProvider := cfg.Section("sandlada").Key("provider").String()
	volatilityPath := cfg.Section("sandlada").Key("volatility").String()
	virusTotalAPIKey := cfg.Section("sandlada").Key("virustotal").String()

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

	if vmProvider == "virtualbox" {
		m = vmInfo
	}

	running, err := m.IsRunning()

	if err != nil {
		log.Printf("Could not check if VM is running, error: %v\nChecking if I can contact agent...", err)

		if ok, err := IsAlive(vmInfo.IP); err == nil {

			if ok {
				log.Println("Agent is responding to health checks, continuing...")
			} else {
				log.Fatal("Agent did not respond with 200 OK")
			}

		} else {
			log.Fatal("Error contacting agent, error: ", err)
		}
	}

	if !running {
		log.Println("Starting VM...")
		if err := m.Start(); err != nil {
			log.Fatal("Could not start VM: ", err)
		}
		log.Println("Started...")
		log.Println("Waiting for contact with agent...")
		for {
			ok, _ := IsAlive(vmInfo.IP)
			if ok {
				log.Println("Agent online!")
				break
			}
			time.Sleep(3 * time.Second)
		}
	} else {
		log.Println("VM is running...")
	}

	log.Println("Sending malware sample...")

	statusCode, err := TransferFile(cfg.Section(opts.AgentVM).Key("ip").String(), opts.Sample)
	if err != nil {
		log.Fatalf("Could not transfer malware sample. Got status code %d, expected 200. %v", statusCode, err)
	}

	if statusCode != 200 {
		log.Fatal("Malware sample was not received correctly...")
	}

	log.Println("Malware sample received...")

	HTTPServer := HttpServer(opts)

	addr := fmt.Sprintf("http://%s/%s", vmInfo.IP, "start?executor="+opts.Executor+"&uuid="+projectUUID)
	status, err := GetRequest(addr)

	if err != nil {
		log.Println("Could not start analysis automatically, please start manually")
	} else {

		if status == 200 {
			log.Println("Analysis has been started...")
		}
	}

	if virusTotalAPIKey != "" {
		if hash, err := CalculateSHA256OfFile(opts.FileWriter, opts.Sample); err == nil {
			resp, err := VirusTotalLookUpHash(hash, virusTotalAPIKey)

			if err != nil {
				log.Println("Virustotal hash lookup failed, error:", err)
			} else {

				dest := opts.Result + "/" + projectUUID
				filename := "virustotal.txt"

				if err := WriteFileToDisk(opts.FileWriter, dest, filename, &resp); err != nil {
					log.Printf("Could not write %s. Error: %v", filename, err)
				} else {
					log.Println("VirusTotal done")
				}
			}

		} else {
			log.Println("Error calculating SHA256 hash: ", err)
		}
	}

	idleConnsClosed := make(chan struct{})

	go func(HTTPServer *http.Server, idleConnsClosed chan struct{}) {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt)
		<-sigint
		log.Println("CTRL+C detected, shutting down")
		ShutdownHTTPServer(HTTPServer)
		close(idleConnsClosed)
	}(HTTPServer, idleConnsClosed)

	// Analysis is finished, gracefully shutdown server
	// But attempt to acquire a memory dump first
	go func(HTTPServer *http.Server, idleConnsClosed chan struct{}, vmInfo *[]provider.VMInfo) {
		requestIP := <-opts.AnalysisFinished
		ShutdownHTTPServer(HTTPServer)
		vm, err := FilterVM(vmInfo, requestIP)

		if err != nil {
			log.Println("Couldn't locate VM in config: ", err)
		} else {

			log.Printf("Acquiring memory capture of %s\n", vm.Name)
			dest := opts.Result + "/" + projectUUID
			err := opts.FileWriter.MkdirAll(dest, os.ModeDir)

			if err != nil {
				log.Println("Failed creating directory, error: ", err)
			} else {
				if err := vm.MemoryDump(dest); err != nil {
					log.Printf("Failed acquiring memory dump of %s, error: %v\n", vm.Name, err)
				}
			}

			if err := ShutdownVm(&vm); err != nil {
				log.Println("Failed stopping VM: ", err)
			} else {
				log.Printf("Virtual machine '%s' has been reverted to previous snapshot\n", vm.Name)
			}
		}

		close(idleConnsClosed)
	}(HTTPServer, idleConnsClosed, &opts.VMInfo)

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
