# NullSec StackTrace

**Stack Trace Analyzer** built with **Perl** - Security analysis of crash dumps and stack traces.

[![Language](https://img.shields.io/badge/Perl-39457E?style=flat-square&logo=perl&logoColor=white)](https://www.perl.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.0.0-blue?style=flat-square)]()
[![NullSec](https://img.shields.io/badge/NullSec-Tool-red?style=flat-square)](https://bad-antics.github.io)

## Overview

NullSec StackTrace is a stack trace security analyzer written in Perl, designed to identify vulnerable functions, suspicious patterns, and attack indicators in crash dumps and stack traces from multiple debuggers.

## Features

- **Multi-Format Support** - WinDbg, GDB, LLDB, Visual Studio
- **Vulnerable Function Detection** - strcpy, gets, sprintf, system, etc.
- **Suspicious Pattern Analysis** - Injection APIs, hook functions
- **Stack Pivot Detection** - Identify abnormal stack jumps
- **ROP Chain Indicators** - Small gadget detection
- **Regex-Powered** - Perl's world-class pattern matching

## Detected Issues

| Category | Functions/Patterns | Severity |
|----------|-------------------|----------|
| Buffer Overflow | strcpy, strcat, gets, sprintf | CRITICAL/HIGH |
| Command Injection | system, popen, exec* | HIGH |
| Format String | printf, syslog (unchecked) | MEDIUM |
| Code Injection | CreateRemoteThread, WriteProcessMemory | CRITICAL |
| Hook Injection | SetWindowsHookEx | MEDIUM |
| APC Injection | NtQueueApcThread | HIGH |

## Installation

```bash
# Perl is pre-installed on most systems

# Install dependencies
cpan install JSON::PP Digest::SHA

# Clone and run
git clone https://github.com/bad-antics/nullsec-stacktrace
cd nullsec-stacktrace
chmod +x stacktrace.pl
./stacktrace.pl
```

## Usage

### Basic Usage

```bash
# Run demo mode
./stacktrace.pl

# Analyze crash dump
./stacktrace.pl crash.txt

# From pipe
cat dump.log | ./stacktrace.pl -

# JSON output
./stacktrace.pl -j trace.txt
```

### Options

```
-h, --help      Show help message
-j, --json      Output results as JSON
-v, --verbose   Enable verbose output
-r, --rop       Enable ROP chain detection
```

### Examples

```bash
# Analyze WinDbg output
./stacktrace.pl windbg_kb.txt

# GDB backtrace
./stacktrace.pl gdb_bt.txt

# Full analysis with ROP detection
./stacktrace.pl --rop -v crash.log
```

## Supported Formats

### WinDbg (kb, kv)

```
00007ff8`1a2b3c4d kernel32!CreateRemoteThread+0x50
00007ff8`1a2b3c5e ntdll!NtCreateThreadEx+0x14
```

### GDB (bt)

```
#0  0x00007ffff7a52a30 in vulnerable_func () at vuln.c:42
#1  0x00007ffff7a52b40 in main () at main.c:10
```

### LLDB

```
frame #0: 0x00007fff8a2b3c4d libsystem`strcpy
frame #1: 0x00007fff8a2b3c5e target`main
```

## Architecture

```
┌───────────────────────────────────────────────────────────┐
│                    Analysis Pipeline                       │
├───────────────────────────────────────────────────────────┤
│                                                           │
│  Input (crash.txt)                                        │
│       │                                                   │
│       ▼                                                   │
│  ┌─────────────────────────────────────────────────────┐ │
│  │              Frame Parser                            │ │
│  │   • WinDbg pattern                                   │ │
│  │   • GDB pattern                                      │ │
│  │   • LLDB pattern                                     │ │
│  │   • Visual Studio pattern                            │ │
│  └──────────────────────┬──────────────────────────────┘ │
│                         │                                 │
│                         ▼                                 │
│  ┌─────────────────────────────────────────────────────┐ │
│  │              Security Analyzers                      │ │
│  ├─────────────────────────────────────────────────────┤ │
│  │  ┌───────────────┐  ┌───────────────┐              │ │
│  │  │   Vulnerable  │  │  Suspicious   │              │ │
│  │  │   Functions   │  │   Patterns    │              │ │
│  │  └───────────────┘  └───────────────┘              │ │
│  │  ┌───────────────┐  ┌───────────────┐              │ │
│  │  │  Stack Pivot  │  │     ROP       │              │ │
│  │  │   Detection   │  │  Indicators   │              │ │
│  │  └───────────────┘  └───────────────┘              │ │
│  └──────────────────────┬──────────────────────────────┘ │
│                         │                                 │
│                         ▼                                 │
│  ┌─────────────────────────────────────────────────────┐ │
│  │              Finding Aggregator                      │ │
│  │   • Sort by severity                                 │ │
│  │   • Add recommendations                              │ │
│  └─────────────────────────────────────────────────────┘ │
│                                                           │
└───────────────────────────────────────────────────────────┘
```

## Vulnerable Functions

```perl
my %vulnerable_functions = (
    # Buffer overflows
    'strcpy'    => { severity => 'HIGH', desc => 'Unbounded string copy' },
    'strcat'    => { severity => 'HIGH', desc => 'Unbounded concatenation' },
    'gets'      => { severity => 'CRITICAL', desc => 'Dangerous input' },
    'sprintf'   => { severity => 'MEDIUM', desc => 'Potential overflow' },
    
    # Command injection
    'system'    => { severity => 'HIGH', desc => 'Command injection risk' },
    'popen'     => { severity => 'HIGH', desc => 'Command injection risk' },
    'execve'    => { severity => 'MEDIUM', desc => 'Process execution' },
);
```

## Suspicious Patterns

```perl
my @suspicious_patterns = (
    { pattern => qr/CreateRemoteThread/i, severity => 'CRITICAL' },
    { pattern => qr/WriteProcessMemory/i, severity => 'HIGH' },
    { pattern => qr/NtQueueApcThread/i, severity => 'HIGH' },
    { pattern => qr/VirtualProtect/i, severity => 'MEDIUM' },
    { pattern => qr/SetWindowsHookEx/i, severity => 'MEDIUM' },
);
```

## Output Example

```
Stack Frames:

    0x00007ff81a2b3c4d kernel32!CreateRemoteThread+80
    0x00007ff81a2b3c5e ntdll!NtCreateThreadEx+20
    0x00007ff81a2b3c70 user32!strcpy+48
    0x00007ff81a2b3c81 msvcrt!gets+32

Security Analysis:

  [CRITICAL] Suspicious Pattern
    Remote thread creation
    Frame: 0x00007ff81a2b3c4d kernel32!CreateRemoteThread+80
    Recommendation: Review context and purpose

  [CRITICAL] Vulnerable Function
    Dangerous input function
    Frame: 0x00007ff81a2b3c81 msvcrt!gets+32
    Recommendation: Consider using safer alternative

  [HIGH] Vulnerable Function
    Unbounded string copy
    Frame: 0x00007ff81a2b3c70 user32!strcpy+48
    Recommendation: Consider using safer alternative
```

## Why Perl?

- **Regex Engine** - Unmatched pattern matching capabilities
- **Text Processing** - Built for parsing text formats
- **One-Liners** - Quick command-line analysis
- **CPAN** - Massive library ecosystem
- **Portable** - Runs everywhere

## Resources

- [Perl Language](https://www.perl.org/)
- [WinDbg Documentation](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/)
- [GDB Manual](https://www.gnu.org/software/gdb/documentation/)
- [CWE Database](https://cwe.mitre.org/)

## NullSec Toolkit

Part of the **NullSec** security toolkit collection:
- 🌐 [Portal](https://bad-antics.github.io)
- 💬 [Discord](https://discord.gg/killers)
- 📦 [GitHub](https://github.com/bad-antics)

## License

MIT License - See [LICENSE](LICENSE) for details.

---

**NullSec** - *Stack trace analysis for crash investigation*
