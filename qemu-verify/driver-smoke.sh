#!/bin/sh
# Phase B smoke: boot patched wimboot + share, screenshot, quit.
cd /home/kain/onyx-server/qemu-verify
export TMPDIR=/home/kain/onyx-server/qemu-verify/tmp
mkdir -p tmp
qemu-system-x86_64 -m 2G -machine pc -cpu qemu64 -smp 2 \
  -accel tcg,thread=multi -display none \
  -kernel webroot/wimboot-final -initrd webroot/files.cpio \
  -drive file=fat:rw:/home/kain/onyx-server/qemu-verify/share,if=ide,media=disk \
  -serial none -monitor tcp:127.0.0.1:4445,server,nowait \
  </dev/null >>qemu-smoke.log 2>&1 &
QP=$!
sleep 420
python3 hmp.py 4445 "screendump shot-smoke.ppm" >/dev/null 2>&1
python3 ppm2png.py shot-smoke.ppm shot-smoke.png
python3 hmp.py 4445 "quit" >/dev/null 2>&1
wait $QP
echo SMOKE_DONE
