DIR ?= .tls
KUBECONFIG ?=

.PHONY: test gen verify install up list clean

test:
	go test ./...

gen:
	go run ./cmd/tlsx gen --dir $(DIR) --reuse-ca

verify:
	go run ./cmd/tlsx verify --dir $(DIR)

install: verify
	go run ./cmd/tlsx install --dir $(DIR) $(if $(KUBECONFIG),--kubeconfig $(KUBECONFIG))

# Regenerate the local PKI and install it into the current cluster.
up: gen install

list:
	go run ./cmd/tlsx list

clean:
	rm -rf $(DIR)
