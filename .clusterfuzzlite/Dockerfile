FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:8c2acffc0898a85ed146e4954c2e15707441d278a73c07af424ee6ace5e73b7c
COPY . $SRC/pipelock
WORKDIR $SRC/pipelock
COPY .clusterfuzzlite/build.sh $SRC/
