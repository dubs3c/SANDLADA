package server

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/google/uuid"
)

func TestReceiveStatusUpdate(t *testing.T) {

	opts := Options{}
	uuid, _ := uuid.NewUUID()
	req, err := http.NewRequest("POST", "/status/"+uuid.String(), nil)
	values := url.Values{}
	values["message"] = []string{"Cool message"}
	values["error"] = []string{"oh no, this is an error"}

	req.Form = values
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(opts.ReceiveStatusUpdate)

	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v. Error message: %s",
			status, http.StatusOK, rr.Body.String())
	}

}

func TestTestReceiveStatusUpdateNoMessage(t *testing.T) {
	opts := Options{}

	req, err := http.NewRequest("POST", "/status/1234", nil)

	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(opts.ReceiveStatusUpdate)

	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code: got %v want %v. Error message: %s",
			status, http.StatusBadRequest, rr.Body.String())
	}

}

type FakeFileWriter struct{}

func (f *FakeFileWriter) Write(filename string, data []byte, perm os.FileMode) error {
	return nil
}

func (f *FakeFileWriter) MkdirAll(dir string, perm os.FileMode) error {
	return nil
}

func (f *FakeFileWriter) Read(filepath string) (*[]byte, error) {
	return &[]byte{}, nil
}

func TestCollectData(t *testing.T) {

	opts := &Options{
		FileWriter: &FakeFileWriter{},
	}

	content := []byte("data")
	filename := "yara.txt"

	reader := bytes.NewReader(content)
	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)
	part, _ := w.CreateFormFile("file", filename)
	io.Copy(part, reader)
	w.Close()

	req, err := http.NewRequest("POST", "/collection/1234", body)
	req.Header.Add("Content-Type", w.FormDataContentType())

	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(opts.CollectData)

	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v. Error message: %s",
			status, http.StatusOK, rr.Body.String())
	}
}

func TestGetRequest(t *testing.T) {
	var body []byte
	headers := map[string]string{}
	headers["x-apikey"] = "1234"
	expected := "Hello Test " + headers["x-apikey"]

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		h := r.Header.Get("x-apikey")
		w.Write([]byte("Hello Test " + h))
	}))
	defer ts.Close()

	_, err := GetRequest(ts.URL, headers, &body)

	if err != nil {
		t.Fatal(err)
	}

	if string(body) != expected {
		t.Errorf("expected '%s', got %s", expected, string(body))
	}
}

func TestSendData(t *testing.T) {
	var data bytes.Buffer
	expected := []byte("Hello Test")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			t.Fatalf("could not parse multipart form")
		}

		multipartFile, _, err := r.FormFile("file")

		if err != nil {
			t.Fatalf("could not parse multipart data")
		}

		defer multipartFile.Close()

		io.Copy(&data, multipartFile)

	}))
	defer ts.Close()

	_, err := SendData(ts.URL, &expected)

	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(data.Bytes(), expected) {
		t.Errorf("expected '%s', got %s", expected, data.Bytes())
	}
}
