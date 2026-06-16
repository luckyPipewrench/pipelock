FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:842269c60ed849f33b50b671e0e4298d14598669fe19f2de37e55ec04092df8e
COPY . $SRC/pipelock
WORKDIR $SRC/pipelock
COPY .clusterfuzzlite/build.sh $SRC/
