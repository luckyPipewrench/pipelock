FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /mock-llm .

FROM alpine:3.21
COPY --from=builder /mock-llm /mock-llm
EXPOSE 8080
ENTRYPOINT ["/mock-llm"]
