package agent

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
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

// StartAnalysis kicks of analysis
func (c *Collection) StartAnalysis(w http.ResponseWriter, req *http.Request) {
	// TODO - Put router in struct

	log.Println("Starting analysis...")
	//go run.BeginNetworkSniffing()
	//go run.StaticAnalysis()
	// host must send executer string if needed. can be set in collection struct maybe
	// should be sent as a body parameter in the POST request
	go c.BehaviorAnalysis("python2")

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(c.UUID.String()))
}

// RunCommand commands in the VM running the agent
func (c *Collection) RunCommand(w http.ResponseWriter, req *http.Request) {

}

/*
	Version 1.
		Each step runs and saves output to disk
		A method polls the struct to check if all steps are done,
		if that is the case, zip the folder containing the files and send to collection.

	Version 2.
		Each step sends its result when ready
		Requires the server to be aware of each step, either via /collection/<step>
		or by including which step is done in the request
		 --> /collection/<uuid>/static
		 --> /collection/<uuid>/dynamic
		 --> /collection/<uuid>/network
		Static can contain many sub-tasks, should send as zip file
		Maybe all requests should be sent as a zip file.
		If I start 1000 different scans several times, I might want to scan the results myself on disk,
		if the all files are zipped, it becomes more overhead
		I could unpack zip files on arrival

	Version 3.
		Each step runs and directly uploads the result to the collection server
		När man startar collection server väljer man om man vill utöver att spara till DB, spara till disk

	Final:
		Agent should always upload directly to collection server. The collection server will then decide
		if the data should be written to disk as well.
*/