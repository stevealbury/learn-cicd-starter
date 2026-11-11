package auth

import (
	"errors"
	"net/http"
	"testing"
)

// A correctly formatted Authorization header should return its API key.
func TestGetAPIKeyValidHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey test-key-123")

	key, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("GetAPIKey() returned an unexpected error: %v", err)
	}
	if key != "test-key-123" {
		t.Errorf("GetAPIKey() key = %q, want %q", key, "test-key-123")
	}
}

// An absent Authorization header should return no key and the specific missing-header error.
func TestGetAPIKeyMissingHeader(t *testing.T) {
	key, err := GetAPIKey(http.Header{})
	if key != "" {
		t.Errorf("GetAPIKey() key = %q, want an empty string", key)
	}
	if !errors.Is(err, ErrNoAuthHeaderIncluded) {
		t.Errorf("GetAPIKey() error = %v, want ErrNoAuthHeaderIncluded", err)
	}
}

// A header with the wrong authentication scheme should be rejected without returning a key.
func TestGetAPIKeyMalformedHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer test-key-123")

	key, err := GetAPIKey(headers)
	if key != "" {
		t.Errorf("GetAPIKey() key = %q, want an empty string", key)
	}
	if err == nil {
		t.Error("GetAPIKey() error = nil, want a malformed-header error")
	}
}
