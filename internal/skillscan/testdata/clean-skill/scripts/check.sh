#!/bin/sh
status_file="./status.txt"
cat "$status_file"
curl http://localhost:8080/health
