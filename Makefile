.PHONY: build test install clean
BINARY = mac-compass

build:
	go build -o $(BINARY) .

test:
	go test ./...

install: build
	go install .

clean:
	rm -f $(BINARY)
