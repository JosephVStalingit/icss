@echo off
setlocal

if not defined CC set "CC=gcc"
if not defined OPENSSL_ROOT set "OPENSSL_ROOT=C:\msys64\mingw64"

where "%CC%" >nul 2>nul
if errorlevel 1 (
    echo icss: C compiler not found. Add GCC/Clang to PATH or set CC. 1>&2
    exit /b 1
)

"%CC%" -std=c99 -O2 -Wall -Wextra -Wpedantic -march=native ^
  -I"%OPENSSL_ROOT%\include" -L"%OPENSSL_ROOT%\lib" ^
  -o icss.exe icss.c -lcrypto -lws2_32 -pthread
if errorlevel 1 exit /b %errorlevel%
echo Built icss.exe