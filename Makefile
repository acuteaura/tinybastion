BASTION_HOST ?= wg-test-1
GO_BIN ?= go1.18beta2

default:
	echo "Choose one of [bastion, client]"

bastion:
	$(GO_BIN) build ./cmd/tinybastion

client:
	$(GO_BIN) build ./cmd/tinyclient

