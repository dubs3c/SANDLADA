package server

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

type Writer interface {
	WriteFile(filename string, data []byte, perm os.FileMode) error
}

type MyFileWriter struct {
}

// ReceiveStatusUpdate receives status updates from the agent, e.g. what's currently running
// or if any errors has ocurred
func (o *Options) ReceiveStatusUpdate(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		errString := fmt.Sprintf("'%s' http method is not supported. Please use POST.", req.Method)
		w.Write([]byte(errString))
		return
	}

	uuid := strings.TrimPrefix(req.URL.Path, "/status/")

	if uuid == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Please specify a UUID"))
		return
	}

	message := req.FormValue("message")
	messageError := req.FormValue("error")

	if message == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Please specify a message"))
		return
	}

	log.Printf("Received status update for %s. Message: %s", uuid, message)

	if len(messageError) > 0 {
		log.Printf("Received status Error: %s", messageError)
	}

	w.WriteHeader(http.StatusOK)
}

// CollectData collects the data that the agent has gathered
func (o *Options) CollectData(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		log.Println("Method not supported!!")
		errString := fmt.Sprintf("'%s' http method is not supported. Please use POST.", req.Method)
		w.Write([]byte(errString))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	uuid := strings.TrimPrefix(req.URL.Path, "/collection/")
	if uuid == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Please specify UUID string as path parameter"))
		return
	}

	var data bytes.Buffer
	err := req.ParseMultipartForm(32 << 20)

	if err != nil {
		log.Println("Could not parse multipart form, error: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}

	multipartFile, multiparFileHeader, err := req.FormFile("file")

	if err != nil {
		log.Println("Could not parse collection data, error: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}

	defer multipartFile.Close()

	io.Copy(&data, multipartFile)

	if err != nil {
		fmt.Println("Error reading collected data: ", err)
		w.WriteHeader(http.StatusInternalServerError)
	}

	filename := multiparFileHeader.Filename
	fileContents := data.Bytes()
	dest := o.Result + "/" + uuid

	if err := writeFileToDisk(o.FileWriter, dest, filename, &fileContents); err != nil {
		log.Printf("Could not write %s. Error: %v", filename, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	log.Printf("Saved result to %s", filename)
	w.WriteHeader(http.StatusOK)
}

// FinishAnalysis notifies the server that a specific analysis is complete.
// The will then attempt to reset the corresponding VM.
func (o *Options) FinishAnalysis(w http.ResponseWriter, req *http.Request) {

	if req.Method != "GET" {
		log.Println("Method not supported!!")
		errString := fmt.Sprintf("'%s' http method is not supported. Please use GET.", req.Method)
		w.Write([]byte(errString))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	requestIPAndPort := req.RemoteAddr

	if requestIPAndPort == "" {
		log.Println("Could not extract remote IP address")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	requestIP := strings.Split(requestIPAndPort, ":")[0]

	// Notify server to shutdown...
	log.Println("Notify to shutdown HTTP server...")
	o.AnalysisFinished <- requestIP

	w.WriteHeader(http.StatusOK)
}

// WriteFile implements the Writer interface that's been created so that ioutil.WriteFile can be mocked
func (m MyFileWriter) WriteFile(filename string, data []byte, perm os.FileMode) error {
	return ioutil.WriteFile(filename, data, perm)
}

// writeFileToDisk Writes files sent for collection to disk
func writeFileToDisk(w Writer, dir string, filename string, data *[]byte) error {
	path := dir + "/" + filename

	if err := os.MkdirAll(dir, os.ModeDir); err != nil {
		return err
	}

	if err := w.WriteFile(path, *data, 0755); err != nil {
		return err
	}

	return nil
}
