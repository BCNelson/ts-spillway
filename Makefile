.PHONY: test test-race test-cover test-e2e lint build clean

test:
	go test ./...

test-race:
	go test -race ./...

test-cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

test-e2e:
	go test -tags e2e -race -count=1 -timeout 10m -v ./e2e/

lint:
	go vet ./...
	golangci-lint run

build:
	go build -o bin/spillway ./cmd/spillway
	go build -o bin/spillway-server ./cmd/spillway-server

clean:
	rm -rf bin/ coverage.out
