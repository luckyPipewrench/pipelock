FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:d98fd3174e3824f362850e675dc4acab8135dc18a0e1efdfbeaacea7fb0c2dbb
COPY . $SRC/pipelock
WORKDIR $SRC/pipelock
COPY .clusterfuzzlite/build.sh $SRC/
