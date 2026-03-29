FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /mock-llm .

FROM alpine:3.21
RUN addgroup -S app && adduser -S app -G app
COPY --from=builder /mock-llm /usr/local/bin/mock-llm
USER app
EXPOSE 8080
ENTRYPOINT ["mock-llm"]
