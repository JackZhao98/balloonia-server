include .env

.PHONY: build run start clean docs

deploy:	docs build

build:
	go build -o ./build/${BINARY} ./cmd/main.go

run:
	.build/${BINARY}

start: build run

clean:
	rm -df ./build

docs:
	rm -rf ./docs/api
	swag init --generalInfo ./cmd/main.go --output ./docs/api

