package tinybastion

import (
	"os"
	"testing"
)

func TestWG(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("need root to test wireguard")
	}
}
