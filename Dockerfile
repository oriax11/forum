# Stage 1: Build
FROM golang:1.22.3-alpine AS builder

# Install build dependencies for SQLite3
RUN apk add --no-cache \
    gcc \
    sqlite-dev

# Set the working directory
WORKDIR /app

# Copy dependency files first for caching
COPY go.mod go.sum ./

# Copy the rest of the application files
COPY . .

# Build the application
RUN go build -o app .

# Stage 2: Runtime
FROM alpine:latest

# Install runtime dependencies for SQLite3
RUN apk add --no-cache \
    sqlite-libs

# Set the working directory
WORKDIR /app

# Copy the built binary from the builder stage
COPY --from=builder /app/app .


# Copy static files (templates, CSS, JS) and database
COPY templates/ ./templates/
COPY static/ ./static/
COPY forum.db .

# Expose the application port
EXPOSE 8080

# Run the application
CMD ["./app"]
