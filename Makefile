
# Create version tag from git tag
VERSION=$(shell git describe | sed 's/^v//')
REPO=cybermaggedon/evs-threatgraph
DOCKER=docker
GO=GOPATH=$$(pwd)/go go

all: evs-threatgraph build

SOURCE=evs-threatgraph.go config.go model.go gaffer.go domain.go

evs-threatgraph: ${SOURCE} go.mod go.sum
	${GO} build -o $@ ${SOURCE}

build: evs-threatgraph
	${DOCKER} build -t ${REPO}:${VERSION} -f Dockerfile .
	${DOCKER} tag ${REPO}:${VERSION} ${REPO}:latest

push:
	${DOCKER} push ${REPO}:${VERSION}
	${DOCKER} push ${REPO}:latest

