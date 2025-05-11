include .env

.PHONY: build run start clean docs

deploy:
	docs build

build:
	go build -o ${BINARY} ./cmd/main.go

run:
	./${BINARY}

start: build run

clean:
	rm -f ${BINARY}

docs:
	rm -rf ./docs/api
	swag init --generalInfo ./cmd/main.go --output ./docs/api

