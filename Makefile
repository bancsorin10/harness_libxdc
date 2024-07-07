all:
	gcc hello.c -o hello
	gcc -fPIC -shared harness.c -o harness.so

run:
	LD_PRELOAD=./harness.so ./hello

