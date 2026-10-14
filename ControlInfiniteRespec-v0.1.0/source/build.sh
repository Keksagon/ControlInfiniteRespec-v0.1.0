#!/usr/bin/env bash
set -euo pipefail
clang++ --target=x86_64-pc-windows-msvc -O2 -fno-exceptions -fno-rtti -fno-stack-protector -fno-builtin -ffreestanding -c ControlInfiniteRespec.cpp -o ControlInfiniteRespec.obj
lld-link /lib /def:kernel32.def /machine:x64 /out:kernel32.lib
lld-link /dll /entry:DllMain /subsystem:windows /nodefaultlib /machine:x64 ControlInfiniteRespec.obj kernel32.lib /out:ControlInfiniteRespec.dll
