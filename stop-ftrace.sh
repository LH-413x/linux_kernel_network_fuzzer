#!/bin/sh

dir=/sys/kernel/debug/tracing

echo 0 > ${dir}/tracing_on
cat ${dir}/trace > trace.txt
echo > trace
cat trace.txt
