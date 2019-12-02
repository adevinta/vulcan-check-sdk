package helpers

import (
	"testing"
)

func TestTarget_IsScannable(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   bool
	}{
		{
			name:   "ValidCIDR",
			target: "1.1.1.1/24",
			want:   true,
		},
		{
			name:   "ValidIP",
			target: "1.1.1.1",
			want:   true,
		},
		{
			name:   "ValidHostname",
			target: "www.google.com",
			want:   true,
		},
		{
			name:   "ValidURL",
			target: "http://www.google.com",
			want:   true,
		},
		{
			name:   "ValidDomainName",
			target: "google.com",
			want:   true,
		},
		{
			name:   "ValidDockerImage",
			target: "registry.hub.docker.com/library/alpine:latest",
			want:   true,
		},
		{
			name:   "ValidAWSAccount",
			target: "arn:aws:iam::111111111111:root",
			want:   true,
		},
		{
			name:   "HostnameNotResolve",
			target: "test.example.com",
			want:   true,
		},
		{
			name:   "PrivateCIDR",
			target: "127.0.0.1/24",
			want:   false,
		},
		{
			name:   "PrivateIP",
			target: "127.0.0.1",
			want:   false,
		},
		{
			name:   "HostnameResolvesPrivate",
			target: "localhost",
			want:   false,
		},
		{
			name:   "URLResolvesPrivate",
			target: "https://localhost",
			want:   false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := IsScannable(tt.target)
			if got != tt.want {
				t.Errorf("Target.IsScannable() = %v, want %v", got, tt.want)
			}
		})
	}
}
