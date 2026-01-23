#!/usr/bin/env perl
# NullSec StackTrace - Stack Trace Analyzer
# Perl security tool demonstrating:
#   - Regular expressions
#   - Hash data structures
#   - Text processing
#   - CPAN ecosystem
#   - One-liners capability
#
# Author: bad-antics
# License: MIT

use strict;
use warnings;
use v5.20;
use feature 'signatures';
no warnings 'experimental::signatures';

use Digest::SHA qw(sha256_hex);
use Time::HiRes qw(gettimeofday tv_interval);
use JSON::PP;
use Getopt::Long;
use File::Basename;

my $VERSION = "1.0.0";

# ANSI Colors
my %colors = (
    red    => "\e[31m",
    green  => "\e[32m",
    yellow => "\e[33m",
    cyan   => "\e[36m",
    gray   => "\e[90m",
    reset  => "\e[0m",
);

sub colored($text, $color) {
    return "$colors{$color}$text$colors{reset}";
}

# Severity levels
my %severity_colors = (
    CRITICAL => 'red',
    HIGH     => 'red',
    MEDIUM   => 'yellow',
    LOW      => 'cyan',
    INFO     => 'gray',
);

# Stack frame structure
package StackFrame {
    sub new($class, %args) {
        return bless {
            address    => $args{address}    // 0,
            module     => $args{module}     // 'unknown',
            function   => $args{function}   // 'unknown',
            offset     => $args{offset}     // 0,
            file       => $args{file}       // '',
            line       => $args{line}       // 0,
            raw        => $args{raw}        // '',
        }, $class;
    }
    
    sub to_string($self) {
        my $addr = sprintf("0x%016x", $self->{address});
        my $loc = $self->{file} ? " at $self->{file}:$self->{line}" : "";
        return "$addr $self->{module}!$self->{function}+$self->{offset}$loc";
    }
}

# Finding structure
package Finding {
    sub new($class, %args) {
        return bless {
            severity       => $args{severity}       // 'INFO',
            category       => $args{category}       // 'Unknown',
            description    => $args{description}    // '',
            frame          => $args{frame},
            recommendation => $args{recommendation} // '',
        }, $class;
    }
}

package main;

# Known vulnerable functions
my %vulnerable_functions = (
    # Buffer overflows
    'strcpy'    => { severity => 'HIGH', desc => 'Unbounded string copy' },
    'strcat'    => { severity => 'HIGH', desc => 'Unbounded string concatenation' },
    'gets'      => { severity => 'CRITICAL', desc => 'Dangerous input function' },
    'sprintf'   => { severity => 'MEDIUM', desc => 'Potential buffer overflow' },
    'vsprintf'  => { severity => 'MEDIUM', desc => 'Potential buffer overflow' },
    'scanf'     => { severity => 'MEDIUM', desc => 'Potential buffer overflow' },
    'sscanf'    => { severity => 'MEDIUM', desc => 'Potential buffer overflow' },
    
    # Format strings
    'printf'    => { severity => 'LOW', desc => 'Check for format string bugs' },
    'fprintf'   => { severity => 'LOW', desc => 'Check for format string bugs' },
    'syslog'    => { severity => 'MEDIUM', desc => 'Potential format string' },
    
    # Memory
    'malloc'    => { severity => 'INFO', desc => 'Dynamic allocation' },
    'free'      => { severity => 'INFO', desc => 'Memory deallocation' },
    'realloc'   => { severity => 'LOW', desc => 'Check for use-after-realloc' },
    
    # System
    'system'    => { severity => 'HIGH', desc => 'Command injection risk' },
    'popen'     => { severity => 'HIGH', desc => 'Command injection risk' },
    'execve'    => { severity => 'MEDIUM', desc => 'Process execution' },
    'execl'     => { severity => 'MEDIUM', desc => 'Process execution' },
    'execlp'    => { severity => 'MEDIUM', desc => 'Process execution' },
);

# Suspicious patterns
my @suspicious_patterns = (
    { pattern => qr/RtlUserThreadStart/i, desc => 'Thread start - check for injection', severity => 'LOW' },
    { pattern => qr/NtCreateThread/i, desc => 'Direct syscall thread creation', severity => 'MEDIUM' },
    { pattern => qr/LdrLoadDll/i, desc => 'DLL loading - check source', severity => 'LOW' },
    { pattern => qr/VirtualAlloc/i, desc => 'Memory allocation - check usage', severity => 'LOW' },
    { pattern => qr/VirtualProtect/i, desc => 'Memory protection change', severity => 'MEDIUM' },
    { pattern => qr/WriteProcessMemory/i, desc => 'Cross-process memory write', severity => 'HIGH' },
    { pattern => qr/CreateRemoteThread/i, desc => 'Remote thread creation', severity => 'CRITICAL' },
    { pattern => qr/NtQueueApcThread/i, desc => 'APC injection indicator', severity => 'HIGH' },
    { pattern => qr/SetWindowsHookEx/i, desc => 'Hook installation', severity => 'MEDIUM' },
    { pattern => qr/GetProcAddress/i, desc => 'Dynamic function resolution', severity => 'INFO' },
);

# Stack frame patterns for parsing
my @frame_patterns = (
    # WinDbg format: module!function+offset
    qr/^(?<addr>[0-9a-fA-F]+)\s+(?<module>\w+)!(?<func>\w+)\+0x(?<off>[0-9a-fA-F]+)/,
    
    # GDB format: #N address in function at file:line
    qr/^#\d+\s+(?<addr>0x[0-9a-fA-F]+)\s+in\s+(?<func>\w+)\s+\(.*?\)\s+at\s+(?<file>.+):(?<line>\d+)/,
    
    # LLDB format
    qr/^\*?\s*frame\s+#\d+:\s+(?<addr>0x[0-9a-fA-F]+)\s+(?<module>\S+)`(?<func>\w+)/,
    
    # Visual Studio format
    qr/^>\s*(?<module>\w+\.dll)!(?<func>\w+)/,
    
    # Simple address format
    qr/^(?<addr>0x[0-9a-fA-F]+)/,
);

# Parse a single stack frame
sub parse_frame($line) {
    $line =~ s/^\s+|\s+$//g;
    return undef unless $line;
    
    for my $pattern (@frame_patterns) {
        if ($line =~ $pattern) {
            my %captures = %+;
            my $addr = $captures{addr} // '0';
            $addr = hex($addr) if $addr =~ /^0x/i;
            $addr = hex($addr) if $addr =~ /^[0-9a-fA-F]+$/;
            
            return StackFrame->new(
                address  => $addr,
                module   => $captures{module} // 'unknown',
                function => $captures{func} // 'unknown',
                offset   => hex($captures{off} // '0'),
                file     => $captures{file} // '',
                line     => $captures{line} // 0,
                raw      => $line,
            );
        }
    }
    
    return undef;
}

# Parse full stack trace
sub parse_stack_trace($text) {
    my @frames;
    for my $line (split /\n/, $text) {
        if (my $frame = parse_frame($line)) {
            push @frames, $frame;
        }
    }
    return \@frames;
}

# Analyze stack trace for security issues
sub analyze_stack($frames) {
    my @findings;
    
    for my $frame (@$frames) {
        my $func = $frame->{function};
        
        # Check vulnerable functions
        if (exists $vulnerable_functions{$func}) {
            my $info = $vulnerable_functions{$func};
            push @findings, Finding->new(
                severity       => $info->{severity},
                category       => 'Vulnerable Function',
                description    => $info->{desc},
                frame          => $frame,
                recommendation => "Consider using safer alternative",
            );
        }
        
        # Check suspicious patterns
        for my $pattern (@suspicious_patterns) {
            if ($frame->{raw} =~ $pattern->{pattern}) {
                push @findings, Finding->new(
                    severity       => $pattern->{severity},
                    category       => 'Suspicious Pattern',
                    description    => $pattern->{desc},
                    frame          => $frame,
                    recommendation => "Review context and purpose",
                );
            }
        }
    }
    
    # Sort by severity
    my %sev_order = (CRITICAL => 0, HIGH => 1, MEDIUM => 2, LOW => 3, INFO => 4);
    @findings = sort { $sev_order{$a->{severity}} <=> $sev_order{$b->{severity}} } @findings;
    
    return \@findings;
}

# Detect stack pivot
sub detect_stack_pivot($frames) {
    return [] unless @$frames >= 2;
    
    my @findings;
    my $prev_addr = $frames->[0]{address};
    
    for my $i (1 .. $#$frames) {
        my $frame = $frames->[$i];
        my $diff = abs($frame->{address} - $prev_addr);
        
        # Large stack jump might indicate pivot
        if ($diff > 0x10000) {
            push @findings, Finding->new(
                severity       => 'HIGH',
                category       => 'Stack Anomaly',
                description    => sprintf("Large stack jump: 0x%x bytes", $diff),
                frame          => $frame,
                recommendation => "Check for stack pivot attack",
            );
        }
        
        $prev_addr = $frame->{address};
    }
    
    return \@findings;
}

# Detect ROP chain indicators
sub detect_rop_indicators($frames) {
    my @findings;
    my $small_gadgets = 0;
    
    for my $frame (@$frames) {
        # Small offsets might indicate gadgets
        if ($frame->{offset} > 0 && $frame->{offset} < 16) {
            $small_gadgets++;
        }
    }
    
    # Multiple small gadgets might indicate ROP
    if ($small_gadgets >= 3) {
        push @findings, Finding->new(
            severity       => 'MEDIUM',
            category       => 'ROP Indicator',
            description    => "Multiple small offset returns detected ($small_gadgets)",
            recommendation => "Check for return-oriented programming",
        );
    }
    
    return \@findings;
}

# Print functions
sub print_banner() {
    say "";
    say "╔══════════════════════════════════════════════════════════════════╗";
    say "║            NullSec StackTrace - Stack Trace Analyzer             ║";
    say "╚══════════════════════════════════════════════════════════════════╝";
    say "";
}

sub print_usage() {
    say "USAGE:";
    say "    stacktrace [OPTIONS] <file>";
    say "";
    say "OPTIONS:";
    say "    -h, --help      Show this help";
    say "    -j, --json      JSON output";
    say "    -v, --verbose   Verbose output";
    say "    -r, --rop       Enable ROP detection";
    say "";
    say "EXAMPLES:";
    say "    stacktrace crash.txt";
    say "    stacktrace --rop dump.log";
    say "    cat trace.txt | stacktrace -";
    say "";
    say "SUPPORTED FORMATS:";
    say "    • WinDbg (kb, kv)";
    say "    • GDB (bt)";
    say "    • LLDB";
    say "    • Visual Studio";
}

sub print_frame($frame) {
    printf "    %s\n", $frame->to_string();
}

sub print_finding($finding) {
    my $color = $severity_colors{$finding->{severity}} // 'gray';
    my $sev = colored("[$finding->{severity}]", $color);
    
    say "";
    say "  $sev $finding->{category}";
    say "    $finding->{description}";
    if ($finding->{frame}) {
        say "    Frame: " . $finding->{frame}->to_string();
    }
    say colored("    Recommendation: $finding->{recommendation}", 'gray');
}

sub print_stats($frames, $findings) {
    say "";
    say colored("═══════════════════════════════════════════", 'gray');
    say "";
    say "  Statistics:";
    printf "    Frames:     %d\n", scalar @$frames;
    printf "    Findings:   %d\n", scalar @$findings;
    
    my %by_sev;
    $by_sev{$_->{severity}}++ for @$findings;
    
    for my $sev (qw(CRITICAL HIGH MEDIUM LOW INFO)) {
        printf "    %-10s  %d\n", "$sev:", $by_sev{$sev} // 0;
    }
}

# Demo mode
sub demo_mode() {
    say colored("[Demo Mode]", 'yellow');
    say "";
    
    # Sample stack trace (WinDbg format)
    my $sample_trace = <<'END_TRACE';
00007ff8`1a2b3c4d kernel32!CreateRemoteThread+0x50
00007ff8`1a2b3c5e ntdll!NtCreateThreadEx+0x14
00007ff8`1a2b3c6f kernel32!WriteProcessMemory+0x100
00007ff8`1a2b3c70 user32!strcpy+0x30
00007ff8`1a2b3c81 msvcrt!gets+0x20
00007ff8`1a2b3c92 target!vulnerable_function+0x42
00007ff8`1a2b3ca3 target!main+0x100
00007ff8`1a2b3cb4 kernel32!BaseThreadInitThunk+0x14
00007ff8`1a2b3cc5 ntdll!RtlUserThreadStart+0x21
END_TRACE
    
    say colored("Parsing sample stack trace...", 'cyan');
    say "";
    
    my $frames = parse_stack_trace($sample_trace);
    
    say "Stack Frames:";
    say "";
    print_frame($_) for @$frames;
    
    say "";
    say "Security Analysis:";
    
    my $findings = analyze_stack($frames);
    my $pivot_findings = detect_stack_pivot($frames);
    my $rop_findings = detect_rop_indicators($frames);
    
    push @$findings, @$pivot_findings, @$rop_findings;
    
    print_finding($_) for @$findings;
    
    print_stats($frames, $findings);
}

# Main
sub main() {
    print_banner();
    
    my $help = 0;
    my $json = 0;
    my $verbose = 0;
    my $rop = 0;
    
    GetOptions(
        'help|h'    => \$help,
        'json|j'    => \$json,
        'verbose|v' => \$verbose,
        'rop|r'     => \$rop,
    ) or die "Error in arguments\n";
    
    if ($help || @ARGV == 0) {
        print_usage();
        say "";
        demo_mode();
        exit 0;
    }
    
    print_usage();
}

main();
