package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		authHeader  string
		expectedKey string
		expectedErr error
	}{
		{
			name:        "missing authorization header",
			authHeader:  "",
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:        "wrong scheme",
			authHeader:  "Bearer sometoken",
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name:        "only scheme provided",
			authHeader:  "ApiKey",
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name:        "valid header",
			authHeader:  "ApiKey validtoken",
			expectedKey: "validtoken",
			expectedErr: nil,
		},
		{
			name:        "valid header with extra parts",
			authHeader:  "ApiKey validtoken extra",
			expectedKey: "validtoken",
			expectedErr: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			headers := http.Header{}
			if tc.authHeader != "" {
				headers.Set("Authorization", tc.authHeader)
			}
			key, err := GetAPIKey(headers)
			if key != tc.expectedKey {
				t.Errorf("expected key %q, got %q", tc.expectedKey, key)
			}

			// Compare error messages.
			if (err == nil && tc.expectedErr != nil) || (err != nil && tc.expectedErr == nil) ||
				(err != nil && tc.expectedErr != nil && err.Error() != tc.expectedErr.Error()) {
				t.Errorf("expected error %v, got %v", tc.expectedErr, err)
			}
		})
	}
}
