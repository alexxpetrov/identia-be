# Build stage
FROM golang:1.23-alpine AS builder
WORKDIR /
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 go build -o /app /cmd/main.go

# Run stage
FROM alpine
WORKDIR /
COPY --from=builder /app .

EXPOSE 4500
ENTRYPOINT [ "./app", "-env", "/.env"]