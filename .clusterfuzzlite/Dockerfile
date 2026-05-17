FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:110a34c2daa035d2ff77a9950e0ba2f7618020df5c505b43a46871d92eee8bff
COPY . $SRC/pipelock
WORKDIR $SRC/pipelock
COPY .clusterfuzzlite/build.sh $SRC/
