package httpclient

import (
	"net/http"
	"time"
)

// DefaultTimeout is the default HTTP request timeout
const DefaultTimeout = 30 * time.Second

// client is the shared HTTP client with timeout configuration
var client *http.Client

func init() {
	client = &http.Client{
		Timeout: DefaultTimeout,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
			DisableKeepAlives:   false,
		},
	}
}

// Get performs an HTTP GET request with timeout
func Get(url string) (*http.Response, error) {
	return client.Get(url)
}

// Post performs an HTTP POST request with timeout
func Post(url, contentType string, body interface{}) (*http.Response, error) {
	return client.Post(url, contentType, nil)
}

// Do executes an HTTP request with timeout
func Do(req *http.Request) (*http.Response, error) {
	return client.Do(req)
}

// GetClient returns the configured HTTP client
func GetClient() *http.Client {
	return client
}

// SetTimeout allows changing the default timeout
func SetTimeout(timeout time.Duration) {
	client.Timeout = timeout
}
