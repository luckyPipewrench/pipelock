FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:8c9ee5a1b2d8509c8df3d613b240b77a11fc3b26ff9b8a6f338db9c86af75189
COPY . $SRC/pipelock
WORKDIR $SRC/pipelock
COPY .clusterfuzzlite/build.sh $SRC/
