FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:3efcff1afbfc8918df51578ff1cd0e4cfc2ecd5ecd6fe0ec7562a026c01b1651
COPY . $SRC/pipelock
WORKDIR $SRC/pipelock
COPY .clusterfuzzlite/build.sh $SRC/
