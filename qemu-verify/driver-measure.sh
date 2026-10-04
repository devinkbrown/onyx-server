#!/bin/sh
# Phase A: boot unpatched wimboot, dump guest RAM, quit. All in one process tree.
cd /home/kain/onyx-server/qemu-verify
qemu-system-x86_64 -m 2G -machine pc -cpu qemu64 -smp 2 \
  -accel tcg,thread=multi -display none \
  -kernel webroot/wimboot -initrd webroot/files.cpio \
  -serial none -monitor tcp:127.0.0.1:4444,server,nowait \
  </dev/null >>qemu2.log 2>&1 &
QP=$!
sleep 110
python3 hmp.py 4444 "pmemsave 0 2147483648 ram.dump"
python3 hmp.py 4444 "quit"
wait $QP
ls -la ram.dump
echo MEASURE_DONE
