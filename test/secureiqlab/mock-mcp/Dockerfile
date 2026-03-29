FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /mock-mcp .

FROM alpine:3.21
COPY --from=builder /mock-mcp /mock-mcp
EXPOSE 8081
ENTRYPOINT ["/mock-mcp"]
