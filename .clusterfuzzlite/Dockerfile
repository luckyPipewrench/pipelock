FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:29c365e4a9e8ec52cbaf8df664454ebcb302e725ec9829a6bbd5ac0e7e987822
COPY . $SRC/pipelock
WORKDIR $SRC/pipelock
COPY .clusterfuzzlite/build.sh $SRC/
