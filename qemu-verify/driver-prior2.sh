#!/bin/sh
# Full verification run v2: heartbeat logging for host-visible progress.
cd /home/kain/onyx-server/qemu-verify
export TMPDIR=$PWD/tmp
mkdir -p tmp shots-prior
rm -f share-prior/result.txt share-prior/alive.txt heartbeat.log
qemu-system-x86_64 -name win11wpe \
  -m 4096 -smp 4 -cpu max -accel tcg,thread=multi -machine q35 \
  -kernel prior/wimboot-final -initrd prior/files.cpio \
  -drive file=fat:rw:/home/kain/onyx-server/qemu-verify/share-prior,media=disk \
  -display none -serial none -monitor tcp:127.0.0.1:4447,server,nowait \
  -no-reboot </dev/null >>qemu-prior2.log 2>&1 &
QP=$!
echo "$(date +%T) qemu pid=$QP" >> heartbeat.log
sleep 20
python3 hmp.py 4447 "info status" >> heartbeat.log 2>&1
echo "$(date +%T) hmp-probe rc=$?" >> heartbeat.log
i=0
while [ $i -lt 150 ]; do
  sleep 60
  i=$((i + 1))
  sz=$(stat -c %s share-prior/result.txt 2>/dev/null || echo none)
  echo "$(date +%T) iter=$i result_size=$sz" >> heartbeat.log
  if [ $((i % 5)) -eq 0 ]; then
    if python3 hmp.py 4447 "screendump shots-prior/run-$i.ppm" >> heartbeat.log 2>&1; then
      python3 ppm2png.py shots-prior/run-$i.ppm shots-prior/run-$i.png >> heartbeat.log 2>&1
      rm -f shots-prior/run-$i.ppm
    else
      echo "$(date +%T) iter=$i screendump FAILED" >> heartbeat.log
    fi
  fi
  if grep -q 'GUEST-STEP: done' share-prior/result.txt 2>/dev/null; then echo "DONE at iter $i"; break; fi
done
python3 hmp.py 4447 "quit" >/dev/null 2>&1
wait $QP
tail -8 share-prior/result.txt 2>/dev/null
echo RUN_DONE
