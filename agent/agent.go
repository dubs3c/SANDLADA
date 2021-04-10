package agent

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"
)

// Options options for agent mode
type Options struct {
	Server    string
	LocalPort int
}

// Task contains the state of each step in the analysis flow
type Task struct {
	StaticAnalysis   string
	BehaviorAnalysis string
	NetworkSniffing  string
}

// Collection contains information about the collection server
// and the ID of a given analysis
type Collection struct {
	Server   string
	UUID     string
	Task     *Task
	Executer string
	FileType string
}

// SendStatus sends a status update to the collection server
// for a given analysis project
func (c *Collection) SendStatus(status string, statusError error) error {
	data := url.Values{}
	data.Set("message", status)
	if statusError != nil {
		data.Set("error", statusError.Error())
	} else {
		data.Set("error", "")
	}
	body := strings.NewReader(data.Encode())
	collectionServer := fmt.Sprintf("%s/status/%s", c.Server, c.UUID)
	_, err := http.Post(collectionServer, "application/x-www-form-urlencoded", body)
	return err
}

// SendData sends collected data to the collection server running on the host machine
func (c *Collection) SendData(content []byte, filename string) (int, error) {
	reader := bytes.NewReader(content)
	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)
	part, _ := w.CreateFormFile("file", filename)
	io.Copy(part, reader)
	w.Close()
	r, err := http.NewRequest("POST", c.Server+"/collection/"+c.UUID, body)
	if err != nil {
		log.Println("Error creating collection request, error:", err)
		return 0, err
	}
	r.Header.Add("Content-Type", w.FormDataContentType())
	client := &http.Client{
		Timeout: 3 * time.Second,
	}
	resp, err := client.Do(r)
	if err != nil {
		return 0, err
	}
	return resp.StatusCode, err
}

// StartAgent starts SANDLÅDA in agent mode
func StartAgent(opts Options) {

	router := http.NewServeMux()
	router.HandleFunc("/health", func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("I'm OK"))
	})

	c := &Collection{
		Server: "http://" + opts.Server,
	}

	router.HandleFunc("/run", c.RunCommand)
	router.HandleFunc("/start", c.StartAnalysis)
	router.HandleFunc("/status", c.Status)
	router.HandleFunc("/transfer", c.ReceiveTransfer)

	HTTPServer := &http.Server{
		Addr:           "0.0.0.0:" + strconv.Itoa(opts.LocalPort),
		Handler:        router,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		IdleTimeout:    15 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	log.Println("Starting Agent Server...")
	idleConnsClosed := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt)
		<-sigint

		// We received an interrupt signal, shut down.
		if err := HTTPServer.Shutdown(context.Background()); err != nil {
			// Error from closing listeners, or context timeout:
			log.Printf("Error shutting down HTTP server: %v", err)
		}
		log.Println("Shutting down HTTP server...")
		close(idleConnsClosed)
	}()

	log.Println("Agent server is ready to rock")
	if err := HTTPServer.ListenAndServe(); err != http.ErrServerClosed {
		// Error starting or closing listener:
		log.Fatalf("HTTP server ListenAndServe: %v", err)
	}

	<-idleConnsClosed
}
