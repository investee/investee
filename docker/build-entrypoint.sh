#!/usr/bin/env bash

cd /src/build && make -j2 toolchains && make -j$(nproc) check

/bin/bash