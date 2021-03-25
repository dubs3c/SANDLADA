package agent

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
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
		Timeout: 3 * time.Second,
	}
	resp, err := client.Do(r)
	if err != nil {
		return 0, err
	}
	return resp.StatusCode, err

}

func (c *Collection) letsGo() {
	d := 120 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()

	go c.BeginNetworkSniffing(ctx)
	go c.StaticAnalysis(ctx)

	go func() {
		c.BehaviorAnalysis(ctx, "python2")
		cancel()
	}()

	// Wait until behavior analysis has canceled or timeout is reached
	<-ctx.Done()
	log.Println("Analysis is done!")
	log.Println(ctx.Err())

	files := []string{"capture.pcap", "behave.txt", "yara.txt", "objdump.txt", "readelf.txt"}
	dir := "/tmp/"

	for _, v := range files {
		go func(filename string) {
			out, err := ioutil.ReadFile(dir + filename)
			if err != nil {
				log.Println("Could not read file", dir+filename)
				return
			} else {
				if code, err := c.SendData(out, filename); err != nil {
					log.Printf("Could not send file %s. Got status code %d. Error: %v", filename, code, err)
					return
				}
				log.Printf("File %s sent to collection server", filename)
			}
		}(v)
	}

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
	c.UUID = uuid.New()

	log.Println("Starting analysis...")

	go c.letsGo()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(c.UUID.String()))
}

func (c *Collection) RunCommand(w http.ResponseWriter, req *http.Request) {

}
