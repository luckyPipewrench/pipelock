FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:8789feaa064d308f5c54af6e3bdfed7bbcbc318bc3425944f0e9575ce46dc06b
COPY . $SRC/pipelock
WORKDIR $SRC/pipelock
COPY .clusterfuzzlite/build.sh $SRC/
