FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:eb5c93a296510c9d159cd9091e72d6a2e00aef974f13785237f4fbecacc7ad4a
COPY . $SRC/pipelock
WORKDIR $SRC/pipelock
COPY .clusterfuzzlite/build.sh $SRC/
