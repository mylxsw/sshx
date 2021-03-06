
example: build
	./bin/example

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/cmd-simulator ./_examples/cmd-simulator/*.go
	go build -o bin/example ./_examples/*.go