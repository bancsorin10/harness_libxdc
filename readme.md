
General harness for tracing and decoding Intel PT
=================================================

# Description

This is a general harness that can be used for tracing a program with Intel PT.
The tracing is setup with linux `perf`. The decoding is done by
[libxdc](https://github.com/nyx-fuzz/libxdc).

It works by taking advantage of `__attribute__((constructor))` which stops
the running program right before main. The address of the main function is
then computed based on the loaded address and the location of main inside the
binary. The location of main inside the binary can be found by using `nm` or
if the binary is stripped one can go to the entry point and watch the address
that is loaded inside the `rdi` register. (more can be seen in a video by
[LiveOverflow](https://www.youtube.com/watch?v=N1US3c6CpSw))

One usage for this can be seen in my [afl++
fork](https://github.com/bancsorin10/AFLplusplus) where applications can be
fuzzed directly in usermode without any emulation layers or other setups.

# Building

The harness depends on `libxdc` which in turn depends on `capstone`. You can
follow the guide in the `libxdc` repo but in short:

For `capstone`:

```
git clone https://github.com/aquynh/capstone.git
cd capstone
git checkout v4
make 
sudo make install
```

For `libxdc`:

```
git clone https://github.com/nyx-fuzz/libxdc.git
cd libxdc
make install
```

For the harness running `make` will create a hello world program and the
harness itself. There should also be a `bitmap` available that can be done
via `make bitmap`. In order to run an application with the harness you can do
the following:

```
LD_PRELOAD=./harness.so ./hello
```
