#!/usr/bin/env bash

cd /src/build && make run &

rm -f /src/sw-serial.log
touch /src/sw-serial.log
chmod 777 /src/sw-serial.log

# Wait until TCP port is available and machine started
while ! nc -z 127.0.0.1 54321; do
    sleep 1
done

tail -F /src/sw-serial.log | socat - TCP:127.0.0.1:54321 & # QEMU_SW_PORT ?= 54321

/bin/bash