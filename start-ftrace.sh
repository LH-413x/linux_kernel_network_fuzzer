#!/bin/sh

dir=/sys/kernel/debug/tracing

echo > ${dir}/trace
sysctl kernel.ftrace_enabled=1
echo function_graph > ${dir}/current_tracer
echo "xfrm*" > ${dir}/set_ftrace_filter
echo 1 > ${dir}/tracing_on