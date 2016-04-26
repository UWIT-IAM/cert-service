#!/bin/bash

# clean various collection directories

cd /logs/cs

# drop old process logs
find . -maxdepth 1 -name 'process-*.log' -mtime +30 -delete

# any other run logs?

