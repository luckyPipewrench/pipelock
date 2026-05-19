FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:803021bd219182072290c9468298ea19a7b474152dd2b537582fb7e8951876bd
COPY . $SRC/pipelock
WORKDIR $SRC/pipelock
COPY .clusterfuzzlite/build.sh $SRC/
