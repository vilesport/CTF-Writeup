#!/bin/bash

qemu-system-x86_64 -S -s \
    -m 64M \
    -kernel /home/user/bzImage \
    -initrd /home/user/initramfs.cpio.gz \
    -append "console=ttyS0 oops=panic panic=1 quiet loglevel=3 kpti=off kaslr" \
    -nographic \
    -no-reboot \
    -monitor /dev/null
