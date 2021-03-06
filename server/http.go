package server

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

// ReceiveStatusUpdate receives status updates from the agent, e.g. what's currently running
// or if any errors has ocurred
func ReceiveStatusUpdate(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		errString := fmt.Sprintf("'%s' http method is not supported. Please use POST.", req.Method)
		w.Write([]byte(errString))
		return
	}
	uuid := strings.TrimPrefix(req.URL.Path, "/status/")
	message := req.FormValue("message")
	messageError := req.FormValue("error")
	log.Printf("Received status update for %s. Message: %s", uuid, message)
	if len(messageError) > 0 {
		log.Printf("Error: %s", messageError)
	}
	// receive status updates for given analysis project
	// status := req.FormValue("message")
	w.WriteHeader(http.StatusOK)
}

// CollectData collects the data that the agent has gathered
func CollectData(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		log.Println("Mehtod not supported!!")
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

	multipartFile, multiparFileHeader, err := req.FormFile("file")

	if err != nil {
		log.Println("Could not parse collection data, error: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	defer multipartFile.Close()

	log.Println(multiparFileHeader.Filename)

	io.Copy(&data, multipartFile)

	if err != nil {
		fmt.Println("Error reading collected data: ", err)
		w.WriteHeader(http.StatusInternalServerError)
	}

	fmt.Println(string(data.Bytes()))

	w.WriteHeader(http.StatusOK)
}
