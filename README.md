# tipc
Rust Bindings for Linux TIPC

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
```sh
$ make test
```