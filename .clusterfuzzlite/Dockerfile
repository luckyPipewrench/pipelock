FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:d2210ed9b824bdf5ad2a9c397dd021596df6282f6ed514a6eca4b3029b606e02
COPY . $SRC/pipelock
WORKDIR $SRC/pipelock
COPY .clusterfuzzlite/build.sh $SRC/
