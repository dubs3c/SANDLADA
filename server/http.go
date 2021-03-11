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

// ReceiveStatusUpdate receives status updates from the agent, e.g. what's currently running
// or if any errors has ocurred
func (o *Options) ReceiveStatusUpdate(w http.ResponseWriter, req *http.Request) {
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
		log.Print("Did not receive UUID for collection request")
		w.Write([]byte("Please specify UUID string as path parameter"))
		w.WriteHeader(http.StatusBadRequest)
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

	io.Copy(&data, multipartFile)

	if err != nil {
		fmt.Println("Error reading collected data: ", err)
		w.WriteHeader(http.StatusInternalServerError)
	}

	store := o.Result + "/" + uuid
	filename := store + "/" + multiparFileHeader.Filename

	if _, err = os.Stat(store); os.IsNotExist(err) {

		if err = os.MkdirAll(store, 0755); err != nil {
			log.Printf("Could not create '%s'\n", store)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

	}

	if err = ioutil.WriteFile(filename, data.Bytes(), 0755); err != nil {
		log.Printf("Could not write %s. Error: %v", filename, err)
		w.WriteHeader(http.StatusInternalServerError)
		return

	}

	log.Printf("Saved result to %s", filename)
	w.WriteHeader(http.StatusOK)
}
