ifeq ($(origin CC),default)
ifeq ($(OS),Windows_NT)
CC := gcc
else
CC := cc
endif
endif
ifeq ($(origin CFLAGS),undefined)
CFLAGS := -std=c99 -O2 -Wall -Wextra -Wpedantic -march=native
endif
ifeq ($(origin LDLIBS),undefined)
LDLIBS := -lcrypto
endif
# The platform libraries are kept separate from LDLIBS so that overriding
# LDLIBS on the command line never breaks the Winsock dependency.
UNAME_S := $(shell uname -s 2>/dev/null)
ifneq (,$(findstring MINGW,$(UNAME_S)))
PLATFORM := windows
else
ifneq (,$(findstring MSYS,$(UNAME_S)))
PLATFORM := windows
else
ifneq (,$(findstring CYGWIN,$(UNAME_S)))
PLATFORM := windows
else
ifneq (,$(findstring Windows_NT,$(OS)))
PLATFORM := windows
else
PLATFORM := unix
endif
endif
endif
endif
ifeq ($(PLATFORM),windows)
SYSLIBS := -lws2_32
EXEEXT := .exe
else
SYSLIBS :=
EXEEXT :=
endif
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

.PHONY: all clean install uninstall

all: icss$(EXEEXT)

icss$(EXEEXT): icss.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS) $(SYSLIBS) -pthread

clean:
	rm -f icss icss.exe

install: icss$(EXEEXT)
	install -d "$(DESTDIR)$(BINDIR)"
	install -m 755 icss$(EXEEXT) "$(DESTDIR)$(BINDIR)/icss"

uninstall:
	rm -f "$(DESTDIR)$(BINDIR)/icss"