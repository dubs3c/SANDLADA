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
	"time"
)

// Options options for server mode
type Options struct {
	AgentVM   string
	AgentIP   string
	Config    string
	Database  string
	LocalPort int
	Result    string
	Sample    string
}

// SendData sends data to agent
func SendData(url string, content *[]byte) error {
	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)

	part, _ := w.CreateFormFile("file", "binary")
	part.Write(*content)

	w.Close()

	r, err := http.NewRequest("POST", url, body)
	r.Header.Add("Content-Type", w.FormDataContentType())

	if err != nil {
		log.Println("Error creating collection request, error:", err)
		return err
	}

	client := &http.Client{
		Timeout: 3 * time.Second,
	}
	_, err = client.Do(r)
	return err
}

// TransferFile transfers the malware sample to the agent
// Meh, this function is only 5 lines, and not easy to test
// might as well break it up.
// I could maybe write a file to disk during test and pass it as filePath
// feels messy though
func TransferFile(url string, filePath string) error {
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	return SendData(url, &content)
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
	/*var m Machine
	m = &VBox{d
		UUID: "7d473abc-0796-4186-bbc4-7144b5399daf",
		Name: "DynLabs",
	}

	if err := m.Stop(); err != nil {
		log.Println("Could not stop virtual machine", err)
	}*/

	router := http.NewServeMux()
	router.HandleFunc("/health", func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("I'm OK"))

	})

	router.HandleFunc("/status/", ReceiveStatusUpdate)
	router.HandleFunc("/collection", CollectData)

	/*if err := server.TransferFile("http://192.168.1.114:9001/transfer", "C:\\Users\\Michael\\go\\src\\github.com\\dubs3c\\SANDLADA\\mal.py"); err != nil {
		log.Println("Could not transfer file, error: ", err)
	}*/

	HTTPServer := &http.Server{
		Addr:           "0.0.0.0:9001",
		Handler:        router,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		IdleTimeout:    15 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	go func() {
		fmt.Println("[+] Starting collection server...")
		log.Fatal(HTTPServer.ListenAndServe())
	}()

	scanner()
}
