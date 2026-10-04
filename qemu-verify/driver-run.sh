#!/bin/sh
# Phase C full run: boot patched chain, poll result.txt, screenshot timeline, quit.
cd /home/kain/onyx-server/qemu-verify
export TMPDIR=/home/kain/onyx-server/qemu-verify/tmp
mkdir -p tmp shots
rm -f share/result.txt
qemu-system-x86_64 -m 2G -machine pc -cpu qemu64 -smp 4 \
  -accel tcg,thread=multi -display none \
  -kernel webroot/wimboot-final -initrd webroot/files.cpio \
  -drive file=fat:rw:/home/kain/onyx-server/qemu-verify/share,if=ide,media=disk \
  -serial none -monitor tcp:127.0.0.1:4446,server,nowait \
  </dev/null >>qemu-run.log 2>&1 &
QP=$!
i=0
lastsize=0
stalled=0
while [ $i -lt 110 ]; do
  sleep 60
  i=$((i + 1))
  python3 hmp.py 4446 "screendump shots/run-$i.ppm" >/dev/null 2>&1
  python3 ppm2png.py shots/run-$i.ppm shots/run-$i.png >/dev/null 2>&1
  rm -f shots/run-$i.ppm
  if grep -q DONE share/result.txt 2>/dev/null; then echo "DONE at iter $i"; break; fi
  if [ -f share/result.txt ]; then
    sz=$(stat -c %s share/result.txt)
    if [ "$sz" = "$lastsize" ]; then
      stalled=$((stalled + 1))
    else
      stalled=0
      lastsize=$sz
    fi
    if [ $stalled -eq 15 ]; then
      echo "STALL_WARNING at iter $i size=$sz"
      tail -3 share/result.txt
      stalled=0
    fi
  fi
done
python3 hmp.py 4446 "quit" >/dev/null 2>&1
wait $QP
ls -la share/result.txt 2>/dev/null
tail -8 share/result.txt 2>/dev/null
echo RUN_DONE
