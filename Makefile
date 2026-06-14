# Makefile for decodeX TUI

BINARY_NAME=decodeX.exe
GO_DIR=tui
GO_FILES=$(GO_DIR)/main.go

build:
	go build -o $(BINARY_NAME) $(GO_FILES)

clean:
	del /f $(BINARY_NAME)

run:
	go run $(GO_FILES)

deps:
	cd $(GO_DIR) && go mod tidy
	cd $(GO_DIR) && go get github.com/charmbracelet/bubbletea
	cd $(GO_DIR) && go get github.com/charmbracelet/lipgloss
	cd $(GO_DIR) && go get github.com/charmbracelet/bubbles/list
	cd $(GO_DIR) && go get github.com/charmbracelet/bubbles/textinput
	cd $(GO_DIR) && go get github.com/charmbracelet/bubbles/viewport
