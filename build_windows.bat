@echo off
setlocal

if not defined CC set "CC=gcc"
if not defined OPENSSL_ROOT set "OPENSSL_ROOT=C:\msys64\mingw64"

where "%CC%" >nul 2>nul
if errorlevel 1 (
    echo icss: C compiler not found. Add GCC/Clang to PATH or set CC. 1>&2
    exit /b 1
)

REM 静态编译：将 libcrypto 和 libgcc 编入二进制，运行时无需 libcrypto-3-x64.dll
REM 若需要动态链接，可去掉 -static -static-libgcc 并改用 -lcrypto
"%CC%" -std=c99 -O2 -Wall -Wextra -Wpedantic -march=native ^
  -static -static-libgcc ^
  -I"%OPENSSL_ROOT%\include" -L"%OPENSSL_ROOT%\lib" ^
  -o icss.exe icss.c "%OPENSSL_ROOT%\lib\libcrypto.a" -lcrypt32 -lws2_32
if errorlevel 1 exit /b %errorlevel%
echo Built icss.exe (static)
