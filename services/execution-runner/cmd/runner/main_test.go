package main

import "testing"

func TestRequireLoopbackAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		address string
		wantErr bool
	}{
		{name: "IPv4 loopback", address: "127.0.0.1:8080"},
		{name: "IPv6 loopback", address: "[::1]:8080"},
		{name: "wildcard address rejected", address: "0.0.0.0:8080", wantErr: true},
		{name: "public address rejected", address: "192.0.2.10:8080", wantErr: true},
		{name: "invalid address rejected", address: "not-an-address", wantErr: true},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := requireLoopbackAddress(test.address)
			if test.wantErr && err == nil {
				t.Fatalf("expected an error for %q", test.address)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("unexpected error for %q: %v", test.address, err)
			}
		})
	}
}
