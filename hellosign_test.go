package hellosign

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestCreateEmbeddedSigningRequest(t *testing.T) {
	mockClient, mockServer := createMockClient("1234")
	defer mockServer.Close()

	// Create new embedded request struct
	embReq := EmbeddedRequest{
		ClientId: "0987",
		FileURL:  "matrix",
		Subject:  "awesome",
		Message:  "cool message bro",
		Signers: []Signer{
			Signer{
				email: "freddy@hellosign.com",
				name:  "Freddy Rangel",
			},
		},
		TestMode: true,
	}
	// Call #CreateEmdeddedSignatureRequest on client struct
	res, err := mockClient.CreateEmbeddedSignatureRequest(embReq)
	assert.Nil(t, err, "Should not return error")
	assert.NotNil(t, res, "Should return response")
}

func createMockClient(key string) (Client, *httptest.Server) {
	mockServer := createMockServer(200, "Everything is cool")

	transport := &http.Transport{
		Proxy: func(req *http.Request) (*url.URL, error) {
			return url.Parse(mockServer.URL)
		},
	}
	mockHTTPClient := &http.Client{Transport: transport}

	client := Client{
		APIKey:     key,
		BaseURL:    mockServer.URL,
		HTTPClient: mockHTTPClient,
	}
	return client, mockServer
}

func createMockServer(status int, body string) *httptest.Server {
	testServer := httptest.NewServer(createMockHandler(status, body))
	return testServer
}

func createMockHandler(status int, _ string) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, "Meow")
	})
}