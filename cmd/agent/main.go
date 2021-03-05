package main

import (
	"log"
	"net/http"
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

	router.HandleFunc("/status", func(w http.ResponseWriter, req *http.Request) {
		// responds with current status of the analysis
		// checks systemtap is running, this is probably done via global variable?
	})

	router.HandleFunc("/transfer", func(w http.ResponseWriter, req *http.Request) {
		// Collection server transfer files to VM via this endpoint
		// Files should be placed in /tmp/
	})

	router.HandleFunc("/start", func(w http.ResponseWriter, req *http.Request) {
		// TODO - Put router in struct
		run := &agent.Collection{
			Server: "http://192.168.1.25:9001",
			UUID:   uuid.New(),
		}
		log.Println("Starting analysis...")
		//go run.BeginNetworkSniffing()
		//go run.StaticAnalysis()
		// host must send executer string if needed. can be set in collection struct maybe
		go run.BehaviorAnalysis("python2")

		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(run.UUID.String()))
	})

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

	router.HandleFunc("/run", func(w http.ResponseWriter, req *http.Request) {
		// Allows for running arbitrary files
		// Remote code execution :)
	})

	HTTPServer := &http.Server{
		Addr:           "0.0.0.0:9001",
		Handler:        router,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		IdleTimeout:    15 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	log.Println("[+] Starting Agent Server...")
	log.Fatal(HTTPServer.ListenAndServe())
}
