all:
	gcc hello.c -o hello
	gcc -Wall -Wextra -fPIC -lxdc -shared harness.c -o harness.so

bitmap:
	dd if=/dev/zero of=test_bitmap bs=1 count=$$((0x10000))

clean:
	rm hello || true
	rm harness.so || true
	rm aux_log || true
	rm test_bitmap || true

re: clean all bitmap run

run:
	LD_PRELOAD=./harness.so ./hello

