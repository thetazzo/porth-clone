#!/usr/bin/env python3
import subprocess;

if __name__ == '__main__':
    subprocess.run(["./porth.py", "sim", "./test/01-arithemtics.porth"]);
    subprocess.run(["./porth.py", "sim", "./test/02-conditions.porth"]);
    subprocess.run(["./porth.py", "sim", "./test/03-loops.porth"]);
    subprocess.run(["./porth.py", "sim", "./test/04-memory.porth"]);
