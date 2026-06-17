FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:dca0fc59dc6dffe9d789180004be423ad1feb42c58d2d2fd2a4fdfb12e2fdb47
COPY . $SRC/pipelock
WORKDIR $SRC/pipelock
COPY .clusterfuzzlite/build.sh $SRC/
