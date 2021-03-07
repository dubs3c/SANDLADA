package agent

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/google/uuid"
)

// Options options for agent mode
type Options struct {
	Server    string
	LocalPort int
}

// StartAgent starts SANDLÅDA in agent mode
func StartAgent() {

	router := http.NewServeMux()
	router.HandleFunc("/health", func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("I'm OK"))
	})

	c := &Collection{
		Server: "http://192.168.1.25:9001",
		UUID:   uuid.New(),
	}

	router.HandleFunc("/run", c.RunCommand)
	router.HandleFunc("/start", c.StartAnalysis)
	router.HandleFunc("/status", c.Status)
	router.HandleFunc("/transfer", c.ReceiveTransfer)

	HTTPServer := &http.Server{
		Addr:           "0.0.0.0:9001",
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
