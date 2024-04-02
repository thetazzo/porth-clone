#!/bin/sh

set -xe

mypy ./porth.py
mypy ./test.py
~/dev/external/pypy3.10-v7.3.15-linux64/bin/pypy3 ./test.py
~/dev/external/pypy3.10-v7.3.15-linux64/bin/pypy3 ./test.py -f ./examples/
~/dev/external/pypy3.10-v7.3.15-linux64/bin/pypy3 ./test.py -f ./euler/

