default:
	echo "Choose one of [bastion, client]"

bastion:
	go1.18beta2 build ./cmd/tinybastion

client:
	go1.18beta2 build ./cmd/tinyclient
