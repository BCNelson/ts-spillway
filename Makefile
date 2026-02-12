.PHONY: test test-race test-cover lint build clean

test:
	go test ./...

test-race:
	go test -race ./...

test-cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

lint:
	go vet ./...
	golangci-lint run

build:
	go build -o bin/spillway ./cmd/spillway
	go build -o bin/spillway-server ./cmd/spillway-server

clean:
	rm -rf bin/ coverage.out
