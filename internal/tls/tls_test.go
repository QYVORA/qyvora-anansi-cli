package tls

import (
	"crypto/tls"
	"testing"
)

func TestTLSVersionName(t *testing.T) {
	tests := []struct {
		v    uint16
		want string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
		{0x0000, "0x0000"},
		{0xabcd, "0xabcd"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tlsVersionName(tt.v)
			if got != tt.want {
				t.Errorf("tlsVersionName(%d) = %q, want %q", tt.v, got, tt.want)
			}
		})
	}
}
