package oidc

import (
	"net/http"
	"testing"
)

func TestDetectJWT(t *testing.T) {
	headerAuthRequest := &http.Request{
		Header: map[string][]string{},
	}
	headerAuthRequest.Header.Add("Authorization", "Bearer TestValue")
	type args struct {
		r *http.Request
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			"JWT in Header",
			args{
				headerAuthRequest,
			},
			"TestValue",
			false,
		},
		{
			"No JWT",
			args{
				&http.Request{
					Header: map[string][]string{},
				},
			},
			"",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DetectJWT(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("DetectJWT() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("DetectJWT() got = %v, want %v", got, tt.want)
			}
		})
	}
}
