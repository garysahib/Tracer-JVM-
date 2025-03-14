# Tracer-JVM-

# Java Vulnerability Tracker via eBPF


A high-performance, production-ready tool that uses eBPF to detect vulnerable Java libraries and methods in running applications with **zero instrumentation** and **minimal performance impact**.

## Overview

This tool leverages Linux eBPF (extended Berkeley Packet Filter) technology to safely monitor Java applications in real-time, detect which libraries and methods are being used, and automatically identify known vulnerabilities without requiring any modifications to your application.

**Key features:**
- **Low overhead** (typically <1% CPU) safe for production use
- **Zero instrumentation** of your Java code or JVM
- **Real-time vulnerability alerts** when vulnerable code executes
- **Package/library usage tracking** for all Java dependencies
- **Method-level analysis** to determine which specific methods are used
- **Comprehensive reports** in JSON format

## Requirements

- Linux kernel 5.5+ (for full eBPF features)
- `libbpf`, `libelf`, `libjson-c` development packages
- LLVM/Clang 10+ for compiling eBPF code
- Java 8+ application to monitor
- [perf-map-agent](https://github.com/jvm-profiling-tools/perf-map-agent) for Java symbol resolution

## Installation

1. **Install dependencies**

   ```bash
   # Ubuntu/Debian
   sudo apt-get install clang llvm libelf-dev libbpf-dev libjson-c-dev bpftool

   # CentOS/RHEL/Fedora
   sudo dnf install clang llvm elfutils-libelf-devel libbpf-devel json-c-devel bpftool
   ```

2. **Install perf-map-agent for Java symbol resolution**

   ```bash
   git clone https://github.com/jvm-profiling-tools/perf-map-agent
   cd perf-map-agent
   cmake .
   make
   sudo cp bin/create-java-perf-map.sh /usr/local/bin/
   ```

3. **Build the Java Vulnerability Tracker**

   ```bash
   ./compile.sh
   ```

## Usage

1. **Basic usage to monitor a Java process:**

   ```bash
   sudo ./java-vuln-tracker -p <JAVA_PID>
   ```

2. **Monitor with vulnerability detection:**

   ```bash
   sudo ./java-vuln-tracker -p <JAVA_PID> -V vulns.json
   ```

3. **Full options:**

   ```bash
   sudo ./java-vuln-tracker -p <JAVA_PID> -d <DURATION_SECONDS> -o <OUTPUT_FILE> -V <VULNS_FILE> -v
   ```

## Vulnerability Database

The vulnerability database is a simple JSON file with the following structure:

```json
{
  "vulnerabilities": [
    {
      "package": "org.apache.log4j",
      "version": "<=2.14.1",
      "cve": "CVE-2021-44228",
      "method": "lookup",
      "description": "Log4Shell vulnerability",
      "severity": 10
    }
  ]
}
```

Fields:
- `package`: Java package name pattern to match
- `version`: Version constraint (supports `<`, `<=`, `>`, `>=`, `==`, `!=`)
- `cve`: CVE identifier
- `method` (optional): Specific vulnerable method name
- `description`: Human-readable description
- `severity`: Severity rating (1-10)

## Example Output

When running, the tool produces immediate alerts when vulnerabilities are detected:

```
!!! VULNERABILITY ALERT !!!
CVE: CVE-2021-44228 (Severity: 10/10)
Package: org.apache.log4j (Version: 2.11.2)
Vulnerable method called: org.apache.logging.log4j.core.lookup.JndiLookup.lookup
Description: Log4Shell vulnerability in Apache Log4j allows attackers to execute arbitrary code
```

The final JSON output contains comprehensive information about all libraries and methods:

```json
{
  "summary": {
    "timestamp": 1678912345,
    "pid": 12345,
    "libraries_found": 86,
    "methods_found": 2341,
    "vulnerabilities_checked": 5
  },
  "libraries": [
    {
      "name": "org.apache.log4j",
      "version": "2.11.2",
      "count": 147,
      "vulnerable": true,
      "cve": "CVE-2021-44228",
      "severity": 10
    },
    ...
  ],
  "top_methods": [
    {
      "name": "java.util.HashMap.get",
      "count": 3892,
      "vulnerable": false
    },
    ...
  ]
}
```

## How It Works

This tool uses eBPF technology to safely observe Java applications at runtime:

1. **Stack Sampling**: Uses Linux perf events to periodically capture stack traces from the JVM
2. **Symbol Resolution**: Maps memory addresses to Java methods using perf-map-agent
3. **Library Identification**: Extracts package/library information from method names
4. **Vulnerability Matching**: Checks libraries and methods against known vulnerabilities
5. **Version Detection**: Attempts to identify library versions from classpath or manifests
6. **Real-time Alerting**: Issues immediate alerts when vulnerable code executes

The eBPF-based approach provides significant advantages:
- **Non-invasive**: No need to modify your application or use special JVM flags
- **Low overhead**: Statistical sampling means minimal performance impact
- **Safe**: Read-only observation with no changes to the running application

## Performance Considerations

The tool is designed for minimal impact on production systems:

- **CPU overhead**: Typically <1% with default 10Hz sampling rate
- **Memory usage**: Approximately 10-20MB depending on application size
- **Sampling rate**: Configurable via `-s` option (higher rates increase accuracy but also overhead)

## Limitations

- Requires root privileges to use eBPF capabilities
- Works only on Linux operating systems
- May not detect very briefly executed methods due to sampling approach
- Package version detection is best-effort and may return "unknown" in some cases

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
