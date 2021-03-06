package server

import (
	"bytes"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"time"
)

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
