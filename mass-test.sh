#!/bin/sh

echo "\n---------------------------------------------------------------------"
echo "                           MyPy ./porth.py                           "
echo "---------------------------------------------------------------------"
if ! mypy ./porth.py ; then
    echo "MyPy python validity failed"
    exit 1
fi
echo "\n---------------------------------------------------------------------"
echo "                           MyPy ./test.py                            "
echo "---------------------------------------------------------------------"
if ! mypy ./test.py ; then
    echp "MyPy python validity failed"
    exit 1
fi
echo "\n---------------------------------------------------------------------"
echo "                          TESTING: ./tests                           "
echo "---------------------------------------------------------------------"
if ! ~/dev/external/pypy3.10-v7.3.15-linux64/bin/pypy3 ./test.py ; then
    echo "Testing has failed"
    exit 1
fi
echo "\n---------------------------------------------------------------------"
echo "                          TESTING: ./examples"
echo "---------------------------------------------------------------------"
if ! ~/dev/external/pypy3.10-v7.3.15-linux64/bin/pypy3 ./test.py run ./examples/ ; then
    echo "Testing has failed"
    exit 1
fi
echo "\n---------------------------------------------------------------------"
echo "                          TESTING: ./euler"
echo "---------------------------------------------------------------------"
if ! ~/dev/external/pypy3.10-v7.3.15-linux64/bin/pypy3 ./test.py run ./euler/ ; then
    echo "Testing has failed"
    exit 1
fi
