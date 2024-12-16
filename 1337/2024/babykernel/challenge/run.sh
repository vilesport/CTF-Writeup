#!/bin/sh

compile() {
    gcc -o ./fs/exp exp.c --static ; 
    cd ./fs ;
    COMPRESS ;
    cd .. 
}

run() {
    compile;
    qemu-system-x86_64 -kernel ./bzImage \
        -m 64M \
        -kernel ./bzImage \
        -initrd ./initramfs.cpio.gz \
        -append "console=ttyS0 oops=panic panic=1 quiet loglevel=3 kpti=off kaslr" \
        -nographic \
        -no-reboot \
        -monitor /dev/null
}

debug() {
    compile;
    qemu-system-x86_64 -S -s -kernel ./bzImage \
        -m 64M \
        -kernel ./bzImage \
        -initrd ./initramfs.cpio.gz \
        -append "console=ttyS0 oops=panic panic=1 quiet loglevel=3 kpti=off kaslr" \
        -nographic \
        -no-reboot \
        -monitor /dev/null
}

_gdb() {
    gdb-multiarch -ex "target remote localhost:1234" -ex "add-symbol-file ./vmlinux"
}

if [ $# -eq 0 ]; then
   debug;
fi

if [ "$1" = "compile" ]; then
    compile
fi
if [ "$1" = "run" ]; then
    run
fi

if [ "$1" = "gdb" ]; then
    _gdb
fi
