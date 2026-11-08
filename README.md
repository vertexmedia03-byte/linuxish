# [iSH](https://ish.app)

> ## 🚀 ARM64 Fork Notice
>
> **This repository is a fork of [ish-app/ish](https://github.com/ish-app/ish)** that adds a
> **native ARM64 guest backend** to upstream iSH's threaded-code interpreter (*Asbestos*,
> renamed from *jit* upstream in 2024 — [ish-app/ish@d375656f](https://github.com/ish-app/ish/commit/d375656f)).
> It emulates AArch64 Linux on Apple Silicon, running alongside the original x86 (i386)
> guest backend.
>
> Upstream Asbestos is a threaded-code interpreter, not a JIT: each basic block is an array
> of pointers to pre-compiled native "gadget" functions that tail-call each other. This fork
> adds an optional native ARM64 guest JIT that translates supported guest instructions into
> host code. Runtime JIT emission is
> enabled in the ARM64 build; on iOS it requires a jailbroken/JIT-enabled environment.
> Strict mode aborts instead of interpreting guest blocks that the translator cannot fully
> compile. Full-coverage AOT images are accepted; partial images are skipped and the runtime JIT
> attempts compilation instead. It does not remove gadget helpers needed for Linux system calls
> and slow paths.
>
> **Key enhancements over upstream:**
> - **Native ARM64 gadget dispatch** — same-architecture, 2-12x faster than x86 for compute
> - **Optional native ARM64 JIT** — translates supported guest blocks at runtime on JIT-enabled devices
> - **48-bit virtual address space** — 4-level page table supports V8/Go/Rust runtimes
> - **Node.js 22 / npm / npx** — V8 guard pages, binary patch, `--jitless` injection
> - **Go and Rust** — large VA reservations, signal frame alignment, FUTEX_WAIT_BITSET, PMULL
> - **Full NEON + Crypto** — AES/SHA/CRC32 instructions for TLS and hashing at native-ish speed
> - **Agent integration** — `ISHShellExecutor` (Obj-C shell API), `DebugServer` (JSON-RPC over HTTP),
>   `Native Offload` (bypass emulation for selected binaries), bind mounts for host↔guest file sharing
> - **iOS-first rootfs** — Alpine 3.21 aarch64 with full `apk` ecosystem and versioned overlay patching
>
> **Performance (ARM64 vs x86, compute-heavy):** C `int_arith_2M` **12x faster**,
> Python `fib(30)` **9.2x faster**, `sum(1M)` **10.2x faster**, shell `seq+awk 100K` **7.2x faster**.
>
> **Full docs:** [README_arm64.md](README_arm64.md) · [中文版](README_arm64_zh.md) ·
> [Performance report](benchmark/BENCHMARK_PERF.md) · [Compatibility report](benchmark/BENCHMARK_COMPAT.md)
>
> ---

<p align="center">
<a href="https://testflight.apple.com/join/ZtGfhNkH">
<img src="https://raw.githubusercontent.com/OpenMinis/ish-arm64/master/.github/testflight_badge.svg" alt="Download on TestFlight" height="60"/>
</a>
</p>

[![Build Status](https://github.com/ish-app/ish/actions/workflows/ci.yml/badge.svg)](https://github.com/ish-app/ish/actions)
[![goto counter](https://img.shields.io/github/search/ish-app/ish/goto.svg)](https://github.com/ish-app/ish/search?q=goto)
[![fuck counter](https://img.shields.io/github/search/ish-app/ish/fuck.svg)](https://github.com/ish-app/ish/search?q=fuck)
[![shit counter](https://img.shields.io/github/search/ish-app/ish/shit.svg)](https://github.com/ish-app/ish/search?q=shit)

<p align="center">
<a href="https://ish.app">
<img src="https://ish.app/assets/github-readme.png">
</a>
</p>

A project to get a Linux shell running on iOS, using usermode x86 emulation and syscall translation.

For the current status of the project, check the issues tab, and the commit logs.

- [App Store page](https://apps.apple.com/us/app/ish-shell/id1436902243)
- [TestFlight beta (ARM64 fork)](https://testflight.apple.com/join/ZtGfhNkH)
- [Discord server](https://discord.gg/HFAXj44)
- [Wiki with help and tutorials](https://github.com/ish-app/ish/wiki)
- [README中文](https://github.com/ish-app/ish/blob/master/README_ZH.md) (如若未能保持最新，请提交PR以更新)

# Hacking

This project has a git submodule, make sure to clone with `--recurse-submodules` or run `git submodule update --init` after cloning.

You'll need these things to build the project:

 - Python 3
   + Meson (`pip3 install meson`)
 - Ninja
 - Clang and LLD (on mac, `brew install llvm`, on linux, `sudo apt install clang lld` or `sudo pacman -S clang lld` or whatever)
 - sqlite3 (this is so common it may already be installed on linux and is definitely already installed on mac. if not, do something like `sudo apt install libsqlite3-dev`)
 - libarchive (`brew install libarchive`, `sudo port install libarchive`, `sudo apt install libarchive-dev`) TODO: bundle this dependency

## Build for iOS

Open the project in Xcode, open `app/iSH.xcconfig`, and change `ROOT_BUNDLE_IDENTIFIER` to something unique. You'll also need to update the development team ID in the project (not target!) build settings. Then click Run. There are scripts that should do everything else automatically. If you run into any problems, open an issue and I'll try to help.

## Build an iSH ARM64 IPA with GitHub Actions

The **Build iSH ARM64 IPA for TrollStore** workflow builds the `iSH-ARM64` scheme with runtime JIT emission and strict untranslated-block checks enabled, then pseudo-signs the app and File Provider executable with `ldid` and their entitlements, including the TrollStore JIT/debug entitlements. Xcode's iOS device SDK does not permit ad-hoc signing during the build; the post-build signature lets iSH read its app-group entitlement at launch. The workflow packages `iSH ARM64.app` as an IPA and uploads the `iSH-ARM64-trollstore-ipa` artifact. It runs on pushes and pull requests to `main`, or can be started manually from the Actions tab.

Download the artifact from a completed workflow run and install it in TrollStore. Use TrollStore's **Open with JIT** action to enable JIT for the app. Strict mode aborts if setup or guest translation fails; on failure it writes the reason, guest PC, and instruction word to `Documents/ISH-JIT-STRICT-FAILURE.txt` so the failure can be diagnosed. Complete AOT images can avoid runtime translation for matching blocks, but the workflow does not bundle AOT images by default. Gadgets remain for Linux system calls and slow paths. The pseudo-signed IPA is not suitable for App Store or ordinary device installation.

This repository contains the [OpenMinis/ish-arm64](https://github.com/OpenMinis/ish-arm64) source at commit `c5c264da19148512167aa493d7bd4e50aae1b74e`, with its iOS build submodules pinned to the revisions in that source commit. The optional Linux-kernel submodule is omitted because this workflow builds the ARM64 app with iSH's built-in kernel. See [LICENSE.md](LICENSE.md) and [LICENSE.IOS](LICENSE.IOS) for the applicable terms.

## Build command line tool for testing

To set up your environment, cd to the project and run `meson build` to create a build directory in `build`. Then cd to the build directory and run `ninja`.

To set up a self-contained Alpine linux filesystem, download the Alpine minirootfs tarball for i386 from the [Alpine website](https://alpinelinux.org/downloads/) and run `./tools/fakefsify`, with the minirootfs tarball as the first argument and the name of the output directory as the second argument. Then you can run things inside the Alpine filesystem with `./ish -f alpine /bin/sh`, assuming the output directory is called `alpine`. If `tools/fakefsify` doesn't exist for you in your build directory, that might be because it couldn't find libarchive on your system (see above for ways to install it.)

You can replace `ish` with `tools/ptraceomatic` to run the program in a real process and single step and compare the registers at each step. I use it for debugging. Requires 64-bit Linux 4.11 or later.

## Logging

iSH has several logging channels which can be enabled at build time. By default, all of them are disabled. To enable them:

- In Xcode: Set the `ISH_LOG` setting in iSH.xcconfig to a space-separated list of log channels.
- With Meson (command line tool for testing): Run `meson configure -Dlog="<space-separated list of log channels>"`.

Available channels:

- `strace`: The most useful channel, logs the parameters and return value of almost every system call.
- `instr`: Logs every instruction executed by the emulator. This slows things down a lot.
- `verbose`: Debug logs that don't fit into another category.
- Grep for `DEFAULT_CHANNEL` to see if more log channels have been added since this list was updated.

# A note on the interpreter

Possibly the most interesting thing I wrote as part of iSH is the interpreter. It's not quite a JIT since it doesn't target machine code. Instead it generates an array of pointers to functions called gadgets, and each gadget ends with a tailcall to the next function; like the threaded code technique used by some Forth interpreters. The result is a speedup of roughly 3-5x compared to emulation using a simpler switch dispatch.

Unfortunately, I made the decision to write nearly all of the gadgets in assembly language. This was probably a good decision with regards to performance (though I'll never know for sure), but a horrible decision with regards to readability, maintainability, and my sanity. The amount of bullshit I've had to put up with from the compiler/assembler/linker is insane. It's like there's a demon in there that makes sure my code is sufficiently deformed, and if not, makes up stupid reasons why it shouldn't compile. In order to stay sane while writing this code, I've had to ignore best practices in code structure and naming. You'll find macros and variables with such descriptive names as `ss` and `s` and `a`. Assembler macros nested beyond belief. And to top it off, there are almost no comments.

So a warning: Long-term exposure to this code may cause loss of sanity, nightmares about GAS macros and linker errors, or any number of other debilitating side effects. This code is known to the State of California to cause cancer, birth defects, and reproductive harm.
