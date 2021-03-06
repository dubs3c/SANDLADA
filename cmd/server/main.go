package main

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dubs3c/SANDLADA/server"
)

// Can be further developed for the interactive version
func scanner() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		fmt.Println(scanner.Text())
	}
}

func main() {

	/*var m Machine
	m = &VBox{
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

	router.HandleFunc("/status/", server.ReceiveStatusUpdate)
	router.HandleFunc("/collection", server.CollectData)

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
