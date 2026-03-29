FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /log-collector .

FROM alpine:3.21
COPY --from=builder /log-collector /log-collector
EXPOSE 9090
ENTRYPOINT ["/log-collector"]
