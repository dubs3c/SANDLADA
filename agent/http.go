package agent

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/h2non/filetype"
)

// Status returns the status of a scan
func (c *Collection) Status(w http.ResponseWriter, req *http.Request) {
	// responds with current status of the analysis
	// checks systemtap is running, this is probably done via global variable?
}

// ReceiveTransfer receives file transfers
func (c *Collection) ReceiveTransfer(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		log.Println("Method not supported!!")
		errString := fmt.Sprintf("'%s' http method is not supported. Please use POST.", req.Method)
		w.Write([]byte(errString))
		return
	}

	var data bytes.Buffer
	err := req.ParseMultipartForm(32 << 20)

	if err != nil {
		log.Println("Could not parse multipart form, error: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	multipartFile, multipartFileHeader, err := req.FormFile("file")

	if err != nil {
		log.Println("Could not parse transferred data, error: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	defer multipartFile.Close()

	if _, err = io.Copy(&data, multipartFile); err != nil {
		log.Println("Error reading data: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	fileType, err := filetype.Archive(data.Bytes())
	if err != nil {
		log.Println("Could not extract filetype")
		c.FileType = "unknown"
	} else {
		c.FileType = fileType.Extension
	}

	if err = ioutil.WriteFile("/tmp/binary", data.Bytes(), 0777); err != nil {
		log.Println("Error reading data: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	log.Printf("Received file '%s' from %s", multipartFileHeader.Filename, req.RemoteAddr)

	w.WriteHeader(http.StatusOK)
}

// GetRequest sends a GET request to a given endpoint
func GetRequest(url string, endpoint string) (int, error) {
	addr := fmt.Sprintf("%s/%s/", url, endpoint)
	r, err := http.NewRequest("GET", addr, bytes.NewBuffer([]byte{}))

	if err != nil {
		log.Println("Error creating collection request, error:", err)
		return 0, err
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := client.Do(r)
	if err != nil {
		return 0, err
	}
	return resp.StatusCode, err

}

func (c *Collection) letsGo() {
	// Specify how long the analysis can run
	maxDurationForAnalysis := 300 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), maxDurationForAnalysis)

	tasksWaitGroup := &sync.WaitGroup{}
	tasksWaitGroup.Add(2)

	// The agent should wait for these
	go c.BeginNetworkSniffing(ctx)
	go c.StaticAnalysis(ctx, tasksWaitGroup)
	go c.BehaviorAnalysis(ctx, c.Executer, tasksWaitGroup)

	// Wait for tasks to finished
	tasksWaitGroup.Wait()
	cancel()

	if ctx.Err().Error() != "context canceled" {
		// TODO - What happens with the analysis if it timesout?
		log.Println("Analysis timed out:", ctx.Err())
	} else {
		log.Println("Analysis is done!")
	}

	files := []string{"capture.pcap", "behave.txt", "yara.txt", "objdump.txt", "readelf.txt", "strings.txt"}
	dir := "/tmp/"

	wg := &sync.WaitGroup{}

	for _, v := range files {
		wg.Add(1)
		go func(filename string, wg *sync.WaitGroup) {
			defer wg.Done()
			out, err := ioutil.ReadFile(dir + filename)
			if err != nil {
				log.Println("Could not read file", dir+filename)
			} else {
				if code, err := c.SendData(out, filename); err != nil {
					log.Printf("Could not send file %s. Got status code %d. Error: %v", filename, code, err)
				} else {
					log.Printf("File %s sent to collection server", filename)
				}
			}
		}(v, wg)
	}

	// Wait for goroutines to finish
	wg.Wait()

	code, err := GetRequest(c.Server, "finished")

	if err != nil {
		log.Println("Error notifying server that the analysis is finished. Error:", err)
		return
	}

	if code == 200 {
		log.Println("Server notified that analysis is complete. This VM will now shutdown...")
	} else {
		log.Printf("Server returned %d when trying to notify that analysis is complete. Expected 200\n", code)
	}
}

// StartAnalysis kicks of analysis
func (c *Collection) StartAnalysis(w http.ResponseWriter, req *http.Request) {

	values := req.URL.Query()

	c.UUID = values.Get("uuid")

	if c.UUID == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Expected uuid parameter to be set, got nothing"))
		return
	}

	c.Executer = values.Get("executor")

	log.Printf("Starting analysis of %s\n", c.UUID)

	go c.letsGo()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(c.UUID))
}

func (c *Collection) RunCommand(w http.ResponseWriter, req *http.Request) {

}
