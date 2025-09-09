#!/bin/sh
# Start the Python runner; AWS Lambda Web Adapter proxies traffic to this process.
exec /var/lang/bin/python3 /var/task/run.py
