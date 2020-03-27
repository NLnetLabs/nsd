# Travis Testing

NSD 4.2.4 and above leverage Travis CI and Cirrus CI to increase coverage of compilers and platforms. Compilers include Clang and GCC; while platforms include Linux, FreeBSD and OS X on AMD64, Aarch64, PowerPC and s390x hardware.

The Unbound Travis configuration file is `.travis.yml`. Travis tests Linux and OS X platforms. Travis configuration does not use top-level keys like `os:` and `compiler:` so there is no matrix expansion. Instead Unbound specifies the exact job to run under the `jobs:` and `include:` keys.

Cirrus CI is a separate build service that complements Travis. The Cirrus configuration file is `.cirrus.yml`. Cirrus tests FreeBSD 12.1 and 13.0 (snap). FreeBSD 13 is expected to be released sometime in 2021.

Android and iOS are not tested because NSD is a server. NSD does not have client components. If you need DNS related client software then use LDNS or Unbound.

## Typical recipe

A typical recipe tests Clang and GCC on various hardware. The hardware includes AMD64, Aarch64, PowerPC and s390x. PowerPC is a little-endian platform, and s390x is a big-endian platform. There are pairs of recipes that are similar to the following.

```
- name: GCC, Linux, Amd64
  os: linux
  dist: bionic
  compiler: gcc
  env:
    - CONFIG_OPTS="--enable-checking --disable-flto"
- name: Clang, Linux, Amd64
  os: linux
  dist: bionic
  compiler: clang
  env:
    - CONFIG_OPTS="--enable-checking --disable-flto"
```

OS X provides a single recipe to test Clang. GCC is not tested because GCC is an alias for Clang.

## Sanitizer builds

Two sanitizer builds are tested using Clang and GCC, for a total of four builds. The first sanitizer is Undefined Behavior sanitizer (UBsan), and the second is Address sanitizer (Asan). The sanitizers are only run on AMD64 hardware. Note the environment includes `TEST_UBSAN=yes` or `TEST_ASAN=yes` for the sanitizer builds.

The recipes are similar to the following.

```
- name: UBsan, GCC, Linux, Amd64
  os: linux
  dist: bionic
  compiler: gcc
  env:
    - TEST_UBSAN=true
    - CONFIG_OPTS="--enable-checking --disable-flto"
- name: UBsan, Clang, Linux, Amd64
  os: linux
  dist: bionic
  compiler: clang
  env:
    - TEST_UBSAN=true
    - CONFIG_OPTS="--enable-checking --disable-flto"
```

When the Travis script encounters a sanitizer it uses different `CFLAGS`.

```
elif [[ "${TEST_UBSAN}" true ]]; then
  export CFLAGS="-DNDEBUG -g2 -O2 -fsanitize=undefined -fno-sanitize-recover"
  ./configure ${CONFIG_OPTS}
  make -j 2 && make cutest && ./cutest
elif [[ "${TEST_ASAN}" true ]]; then
  export CFLAGS="-DNDEBUG -g2 -O2 -fsanitize=address"
  ./configure ${CONFIG_OPTS}
  make -j 2 && make cutest && ./cutest
```

## Cirrus CI

Cirrus is a separate CI service that is documented with Travis. Cirrus tests FreeBSD 12.1 and 13.0 (snap) with the standard build and audit. A typical Cirrus recipe is shown below.

```
- name: Standard build, FreeBSD 12.1
  freebsd_instance:
    image_family: freebsd-12-1
  pkginstall_script:
    - pkg update -f
    - pkg install -y gmake autoconf automake libevent
  configure_script:
    - autoconf && autoheader
    - ./configure --enable-checking
  compile_script:
    - make -j 3
    - make cutest
  test_script:
    - ./cutest
```

## Checksec

The NSD makefile includes a recipe called `audit`. The `audit` recipe downloads a tool called `checksec`, and runs `checksec` against the programs `nsd`, `nsd-checkconf`, `nsd-checkzone`, `nsd-control` and `nsd-mem`. Checksec checks the binaries for basic hardening, like GOT and PLT hardening, stack protectors, NX stacks, PIC and PIE (ASLR), and fortified sources.

The `audit` recipe runs the following instructions.

```
audit: nsd nsd-checkconf nsd-checkzone nsd-control nsd-mem checksec
	./checksec --file=nsd
	./checksec --file=nsd-checkconf
	./checksec --file=nsd-checkzone
	./checksec --file=nsd-control
	./checksec --file=nsd-mem
```

A typical output on modern Linux looks similar to the following.

```
./checksec --file=nsd
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable  FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   1077 Symbols     Yes	9		20	nsd

./checksec --file=nsd-checkconf
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable  FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   243 Symbols     Yes	6		9	nsd-checkconf
...
```

While modern Linux looks fine, the BSDs do not. NSD built on the FreeBSD, NetBSD or OpenBSD should use additional hardening.

```
./checksec --file=nsd
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable  FILE
No RELRO        No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   3139 Symbols     No	       1		2	nsd
./checksec --file=nsd-checkconf
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable  FILE
No RELRO        No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   1529 Symbols     No	       1		2	nsd-checkconf
...
```

For a list of some of the flags to use on the BSDs see Red Hat's blog [Recommended compiler and linker flags for GCC](https://developers.redhat.com/blog/2018/03/21/compiler-and-linker-flags-gcc/).
