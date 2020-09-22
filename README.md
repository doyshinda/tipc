# tipc
Rust Bindings for some of the common Linux TIPC operations.

## Prerequisites
* Linux OS
* clang
* TIPC kernel module enabled (`sudo modprobe tipc`)

## Building tipc
```sh
$ git clone https://github.com/doyshinda/tipc.git
$ cd tipc
$ cargo build [--release]
```

## Testing
By default, Rust will run tests in parallel, which causes havoc when many different tests are trying to create/join the same TIPC group. Use the following make target, which pins the number of test threads to 1:
```sh
$ make test
```

Alternatively, you can invoke the following cargo command directly:
```sh
cargo test -- --test-threads=1
```
