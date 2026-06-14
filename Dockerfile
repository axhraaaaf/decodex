# Multi-stage Dockerfile for decodeX (Go TUI + Python Backend)

# Stage 1: Build the Go TUI
FROM golang:1.22 AS builder

WORKDIR /app
COPY tui/go.mod tui/go.sum ./
RUN go mod download

COPY tui/main.go ./
RUN go build -o decodeX main.go

# Stage 2: Setup Python environment and copy the TUI
FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the package
COPY decodeX ./decodeX
COPY requirements.txt ./
COPY main.py ./

# Install python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the TUI binary from builder
COPY --from=builder /app/decodeX /usr/local/bin/decodeX

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Default command launches the TUI
ENTRYPOINT ["decodeX"]
