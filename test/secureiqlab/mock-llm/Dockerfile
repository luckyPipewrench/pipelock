FROM golang:1.25-alpine@sha256:8e02eb337d9e0ea459e041f1ee5eece41cbb61f1d83e7d883a3e2fb4862063fa AS builder
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /mock-llm .

FROM alpine:3.21@sha256:c3f8e73fdb79deaebaa2037150150191b9dcbfba68b4a46d70103204c53f4709
RUN addgroup -S app && adduser -S app -G app
COPY --from=builder /mock-llm /usr/local/bin/mock-llm
USER app
EXPOSE 8080
ENTRYPOINT ["mock-llm"]
