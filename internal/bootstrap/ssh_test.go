package bootstrap

import (
	"context"
	"testing"
)

func TestRejectPublicLoopbackAndHostname(t *testing.T) {
	for _, host := range []string{"8.8.8.8", "127.0.0.1", "::1", "example.com", "0.0.0.0"} {
		if _, e := Install(context.Background(), Request{Host: host, Port: 22, User: "root"}); e == nil {
			t.Fatal("unsafe SSH target accepted", host)
		}
	}
}
