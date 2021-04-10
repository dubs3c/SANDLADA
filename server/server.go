package server

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"os/signal"
	"strconv"
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
	FileWriter       Writer
}

// IsAlive tries to contact the agent running inside the VM
func IsAlive(ip string) (bool, error) {

	resp, err := GetRequest(ip, "health")

	if err != nil {
		return false, err
	}

	if resp == 200 {
		return true, nil
	}

	return false, nil
}

// GetRequest sends a GET request to a given endpoint
func GetRequest(domain string, endpoint string) (int, error) {
	addr := fmt.Sprintf("http://%s/%s", domain, endpoint)
	r, err := http.NewRequest("GET", addr, bytes.NewBuffer([]byte{}))

	if err != nil {
		log.Println("Error creating collection request, error:", err)
		return 0, err
	}

	client := &http.Client{
		Timeout: 3 * time.Second,
	}
	resp, err := client.Do(r)

	if err != nil {
		return 0, err
	}

	defer resp.Body.Close()

	return resp.StatusCode, err
}

// SendData sends data to agent
func SendData(url string, content *[]byte) (int, error) {
	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)

	part, _ := w.CreateFormFile("file", "binary")
	part.Write(*content)

	w.Close()

	r, err := http.NewRequest("POST", url, body)
	r.Header.Add("Content-Type", w.FormDataContentType())

	if err != nil {
		log.Println("Error creating collection request, error:", err)
		return 0, err
	}

	client := &http.Client{
		Timeout: 3 * time.Second,
	}
	resp, err := client.Do(r)
	if err != nil {
		return 0, err
	}
	return resp.StatusCode, err
}

// TransferFile transfers the malware sample to the agent
func TransferFile(ip string, filePath string) (int, error) {
	content, err := ioutil.ReadFile(filePath)

	if err != nil {
		return 0, err
	}

	statusCode, err := SendData("http://"+ip+"/transfer", &content)
	return statusCode, err
}

// Can be further developed for the interactive version
func scanner() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		fmt.Println(scanner.Text())
	}
}

func httpServer(opts Options) *http.Server {
	router := http.NewServeMux()
	router.HandleFunc("/health", func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("I'm OK"))

	})

	router.HandleFunc("/status/", opts.ReceiveStatusUpdate)
	router.HandleFunc("/collection/", opts.CollectData)
	router.HandleFunc("/finished/", opts.FinishAnalysis)

	HTTPServer := &http.Server{
		Addr:           "0.0.0.0:" + strconv.Itoa(opts.LocalPort),
		Handler:        router,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		IdleTimeout:    15 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	return HTTPServer
}

// StartServer starts SANDLÅDA in server mode
func StartServer(opts Options) {
	var m provider.Machine
	cfg, err := ini.Load(opts.Config)
	if err != nil {
		log.Fatal("Fail to read configuration file: ", err)
	}

	// Generate UUID for sample for unique identification
	projectUUID := uuid.New()
	vmProvider := cfg.Section("sandlada").Key("provider").String()
	virusTotalAPIKey := cfg.Section("sandlada").Key("virustotal").String()
	snapshot := cfg.Section(opts.AgentVM).Key("snapshot").String()

	vmInfo := &provider.VMInfo{
		UUID:     cfg.Section(opts.AgentVM).Key("uuid").String(),
		Name:     opts.AgentVM,
		Path:     cfg.Section("virtualbox").Key("path").String(),
		Snapshot: snapshot,
		IP:       cfg.Section(opts.AgentVM).Key("ip").String(),
	}

	opts.VMInfo = append(opts.VMInfo, *vmInfo)
	opts.AnalysisFinished = make(chan string, 1)
	opts.FileWriter = &MyFileWriter{}

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
		for true {
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

	HTTPServer := httpServer(opts)

	status, err := GetRequest(vmInfo.IP, "start?executor="+opts.Executor+"&uuid="+projectUUID.String())

	if err != nil {
		log.Println("Could not start analysis automatically, please start manually")
	}

	if status == 200 {
		log.Println("Analysis has been started...")
	}

	if virusTotalAPIKey != "" {
		if hash, err := CalculateSHA256(opts.Sample); err == nil {
			resp, err := VirusTotalLookUpHash(hash, virusTotalAPIKey)

			if err != nil {
				log.Println("Virustotal hash lookup failed, error:", err)
			} else {

				dest := opts.Result + "/" + projectUUID.String()
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

	go func(HTTPServer *http.Server, idleConnsClosed chan struct{}) {
		// Analysis is finished, gracefully shutdown server
		requestIP := <-opts.AnalysisFinished
		ShutdownHTTPServer(HTTPServer)
		opts.ShutdownVm(requestIP)
		close(idleConnsClosed)
	}(HTTPServer, idleConnsClosed)

	go func() {
		log.Println("Starting collection server...")
		if err := HTTPServer.ListenAndServe(); err != http.ErrServerClosed {
			// Error starting or closing listener:
			log.Fatalf("HTTP server ListenAndServe: %v", err)
		}
	}()

	<-idleConnsClosed

	log.Println("Server done, bye!")

}
