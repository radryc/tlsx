DIR ?= .tls
KUBECONFIG ?=

.PHONY: test gen verify install list clean

test:
	go test ./...

gen:
	go run ./cmd/tlsx gen --dir $(DIR) --reuse-ca

verify:
	go run ./cmd/tlsx verify --dir $(DIR)

install: verify
	go run ./cmd/tlsx install --dir $(DIR) $(if $(KUBECONFIG),--kubeconfig $(KUBECONFIG))

list:
	go run ./cmd/tlsx list

clean:
	rm -rf $(DIR)
