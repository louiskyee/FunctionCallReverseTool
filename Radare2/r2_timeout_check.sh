#!/bin/bash

input_file="$1"
timeout_seconds="$2"

timeout --kill-after=10 $timeout_seconds r2 -qc "aaa" "$input_file" > /dev/null 2>&1

if [ $? -eq 0 ]; then
    echo "true"
else
    echo "false"
fi