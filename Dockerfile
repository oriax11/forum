FROM golang:1.22.3 

# Install build dependencies for SQLite3
RUN apt-get update && apt-get install -y \
    gcc \
    libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY go.mod go.sum ./
COPY . .

EXPOSE 7080

CMD ["go","run","main.go"]
