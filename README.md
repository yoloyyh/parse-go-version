# parse-go-version
parse go ELF version support go 1.13 ~ 1.22

# Reference
use rust parse go elf get version, refence: https://github.com/golang/go/blob/master/src/debug/buildinfo/buildinfo.go

other ways to get go version：

1、 go version elf

2、strings elf | grep "^go1.*"

3、parse elf


# Usage
```
cargo run --file-path
```
