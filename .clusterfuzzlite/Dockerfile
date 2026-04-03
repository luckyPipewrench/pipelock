FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:754d5b4e94572c65a85d7644958aa085be9e76058e10390e6a76e2f85324c655
COPY . $SRC/pipelock
WORKDIR $SRC/pipelock
COPY .clusterfuzzlite/build.sh $SRC/
