package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// HttpServer returns a HttpServer
func HttpServer(opts Options) *http.Server {
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

	_, err = io.Copy(&data, multipartFile)

	if err != nil {
		fmt.Println("Error reading collected data: ", err)
		w.WriteHeader(http.StatusInternalServerError)
	}

	filename := multiparFileHeader.Filename
	fileContents := data.Bytes()
	dest := o.Result + "/" + uuid

	if err := WriteFileToDisk(o.FileWriter, dest, filename, &fileContents); err != nil {
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

func ShutdownHTTPServer(HTTPServer *http.Server) error {
	// We received an interrupt signal, shut down.
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	return HTTPServer.Shutdown(ctx)
}

// IsAlive tries to contact the agent running inside the VM
func IsAlive(ip string) (bool, error) {

	addr := fmt.Sprintf("http://%s/%s", ip, "health")
	code, err := GetRequest(addr, map[string]string{}, &[]byte{})

	if err != nil {
		return false, err
	}

	if code == 200 {
		return true, nil
	}

	return false, nil
}

// GetRequest sends a GET request to a given endpoint
func GetRequest(url string, headers map[string]string, body *[]byte) (int, error) {
	r, err := http.NewRequest("GET", url, bytes.NewBuffer([]byte{}))

	if err != nil {
		log.Println("Error creating collection request, error:", err)
		return 0, err
	}

	if len(headers) != 0 {
		for header, value := range headers {
			r.Header.Add(header, value)
		}
	}

	client := &http.Client{
		Timeout: 3 * time.Second,
	}

	resp, err := client.Do(r)

	if err != nil {
		return 0, err
	}

	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)

	if err == nil {
		*body = bodyBytes
	}

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

	defer resp.Body.Close()

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
