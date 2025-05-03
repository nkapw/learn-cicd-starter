package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		header  http.Header
		wantKey string
		wantErr error
	}{
		{
			name:    "Missing Authorization header",
			header:  http.Header{},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed header - missing ApiKey prefix",
			header: http.Header{
				"Authorization": []string{"Bearer sometoken"},
			},
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name: "Malformed header - not enough parts",
			header: http.Header{
				"Authorization": []string{"ApiKeyOnly"},
			},
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name: "Valid header",
			header: http.Header{
				"Authorization": []string{"ApiKey my-secret-key"},
			},
			wantKey: "my-secret-key",
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.header)

			if gotKey != tt.wantKey {
				t.Errorf("expected key %q, got %q", tt.wantKey, gotKey)
			}

			if (err != nil && tt.wantErr == nil) || (err == nil && tt.wantErr != nil) {
				t.Fatalf("expected error %v, got %v", tt.wantErr, err)
			}

			if err != nil && tt.wantErr != nil && err.Error() != tt.wantErr.Error() {
				t.Errorf("expected error message %q, got %q", tt.wantErr.Error(), err.Error())
			}
		})
	}
}
