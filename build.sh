#!/bin/sh

set -xe

nasm -f elf64 output.asm
ld -o output hello.o
