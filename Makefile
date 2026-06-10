# Makefile for decodeX TUI

BINARY_NAME=decodeX.exe
GO_FILES=main.go

build:
	go build -o $(BINARY_NAME) $(GO_FILES)

clean:
	del /f $(BINARY_NAME)

run:
	go run $(GO_FILES)

deps:
	go mod tidy
	go get github.com/charmbracelet/bubbletea
	go get github.com/charmbracelet/lipgloss
	go get github.com/charmbracelet/bubbles/list
	go get github.com/charmbracelet/bubbles/textinput
	go get github.com/charmbracelet/bubbles/viewport
