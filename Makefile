# Purpose: Makefile for building the C code for CodeQL analysis.
build:
	cc -c openssl/*.c
	echo "This task is only usefull for CodeQL analysis. You don't need to run it."
