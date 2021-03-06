package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/dubs3c/SANDLADA/agent"
	"github.com/google/uuid"
)

func main() {

	router := http.NewServeMux()
	router.HandleFunc("/health", func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("I'm OK"))
	})

	c := &agent.Collection{
		Server: "http://192.168.1.25:9001",
		UUID:   uuid.New(),
	}

	// ./agent --srv 192.168.1.25:9001 --lport 9001

	router.HandleFunc("/run", c.RunCommand)
	router.HandleFunc("/start", c.StartAnalysis)
	router.HandleFunc("/status", c.Status)
	router.HandleFunc("/transfer", c.Transfer)

	HTTPServer := &http.Server{
		Addr:           "0.0.0.0:9001",
		Handler:        router,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		IdleTimeout:    15 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	log.Println("[+] Starting Agent Server...")
	idleConnsClosed := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt)
		<-sigint

		// We received an interrupt signal, shut down.
		if err := HTTPServer.Shutdown(context.Background()); err != nil {
			// Error from closing listeners, or context timeout:
			log.Printf("HTTP server Shutdown: %v", err)
		}
		close(idleConnsClosed)
	}()

	if err := HTTPServer.ListenAndServe(); err != http.ErrServerClosed {
		// Error starting or closing listener:
		log.Fatalf("HTTP server ListenAndServe: %v", err)
	}

	<-idleConnsClosed
}
