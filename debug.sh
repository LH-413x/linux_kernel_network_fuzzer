#!/bin/sh

echo 123 | sudo -S "./start-ftrace.sh"
bash -c "$@"
echo 123 | sudo -S "./stop-ftrace.sh"