package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
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

	router.HandleFunc("/status/", func(w http.ResponseWriter, req *http.Request) {
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
	})

	router.HandleFunc("/collection", func(w http.ResponseWriter, req *http.Request) {
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

	})

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

/* https://wiki.ubuntu.com/Kernel/Systemtap

Need to get PID of sample and pass it to systemtap, like so:

stap_start = time.time()
        self.proc = subprocess.Popen([
            "staprun", "-vv",
            "-x", str(os.getpid()),
            "-o", "stap.log",
            path,
        ], stderr=subprocess.PIPE)

		sudo stap -p4 -r $(uname -r) strace.stp -m stap_ -v


----------------------------



[DYNAMIC]
pid = startaProgram()

go startaSystemTap(pid)
go startaPcap()
go startaX()

if not pid:
	programDone()
	StopCoroutines()
	collectInformation() -> Pcap, systemtap, logs(?)
	revertBackToSnapshot()

*/
