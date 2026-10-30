 
# Recursive DLL Reverse Engineering Automation (REA)

A Python-based batch reverse engineering tool for recursively analysing Windows DLL files using **ILSpy** and **Ghidra**.

REA automatically identifies managed .NET, native, and mixed-mode DLLs, selects the appropriate analysis engine, and exports decompiled source code, function information, and analysis metadata while preserving the original directory structure.

## Features

- **Recursive DLL discovery** — Scans input directories and subdirectories for `.dll` files.
- **PE analysis** — Identifies PE architecture, sections, CLR metadata, and binary type without third-party Python packages.
- **Automatic binary classification** — Managed .NET, native, mixed-mode, and unresolved CLR-header binaries.
- **Managed DLL analysis using ILSpy** — Exports reconstructed C# source code and Intermediate Language (IL).
- **Native DLL analysis using Ghidra** — Enumerates functions and exports C-like pseudocode.
- **Temporary native DLL staging** — Copies native DLLs into short local temporary paths before invoking Ghidra, avoiding Windows path parsing issues involving spaces and parentheses.
- **SHA-256 hashing** — Records file hashes and sizes.
- **Structured output** — Preserves the original directory hierarchy.
- **Batch reporting** — Generates individual processing reports and an overall batch summary.
- **Error handling** — Records failures and supports partial-success reporting.

## Architecture

```text
                    INPUT DIRECTORY
                           |
                           v
                Recursive DLL Discovery
                           |
                           v
                     PE Inspection
                           |
                           v
                  Binary Classification
                           |
              +------------+------------+
              |                         |
              v                         v
       Managed / Mixed             Native / Mixed
              |                         |
              v                         v
           ILSpy                     Ghidra
              |                         |
       +------+-------+          +------+-------+
       |              |          |              |
       v              v          v              v
    C# Source      IL Export   Function      C Pseudocode
                              Metadata
              |                         |
              +------------+------------+
                           |
                           v
                  Analysis Reports
                           |
                           v
                  Batch Summary JSON
```

## Requirements

### Operating system
- Windows 10 or Windows 11
- Python 3.10 or later
- .NET SDK/runtime required by ILSpy
- Ghidra with its headless launcher

### Install ILSpy

```powershell
dotnet tool install --global ilspycmd
```

Verify:

```powershell
ilspycmd --version
```

Ensure the .NET global tools directory is available in PATH.

### Install Ghidra

Install Ghidra and locate its headless launcher:

```text
C:\re\GHIDRA\support\analyzeHeadless.bat
```

REA uses Ghidra Headless Analyzer and a Java-based Ghidra script to export decompiled functions.

## Installation

Clone the repository:

```powershell
git clone https://github.com/codarabbit/REA.git
cd REA
```

No additional Python packages are required by the current implementation.

## Usage

### Basic execution

```powershell
python REA.py --input "C:\Path\To\DLLs" --output "C:\RE_Results"
```

### Specify Ghidra installation

```powershell
python REA.py `
  --input "C:\Path\To\DLLs" `
  --output "C:\RE_Results" `
  --ghidra "C:\re\GHIDRA\support\analyzeHeadless.bat"
```

### Specify a local temporary directory

Native DLLs are copied into temporary local workspaces before Ghidra analysis.

```powershell
python REA.py `
  --input "C:\Program Files\Vendor\Product" `
  --output "C:\RE_Results" `
  --ghidra "C:\re\GHIDRA\support\analyzeHeadless.bat" `
  --temp-dir "C:\re\tmp"
```

### Preserve temporary analysis folders

By default, temporary Ghidra workspaces are deleted after processing.

Use `--keep-temp` to retain them for troubleshooting:

```powershell
python REA.py `
  --input "C:\Path\To\DLLs" `
  --output "C:\RE_Results" `
  --temp-dir "C:\re\tmp" `
  --keep-temp
```

## Command-line Arguments

| Argument | Required | Description |
|---|---|---|
| `--input` | Yes | Root directory containing DLL files |
| `--output` | Yes | Directory where analysis results are stored |
| `--ghidra` | No | Path to `analyzeHeadless.bat` |
| `--temp-dir` | No | Local base directory for temporary Ghidra workspaces |
| `--keep-temp` | No | Retains temporary workspaces after processing |

## Output Structure

REA preserves the relative directory structure of the original DLL collection.

```text
RE_Results/
│
├── ModuleA/
│   ├── ARM_Helper/
│   │   ├── analysis_summary.json
│   │   ├── processing_result.json
│   │   └── Generated_Native/
│   │       ├── functions.json
│   │       ├── functions.txt
│   │       ├── ghidra_console.log
│   │       ├── GhidraScripts/
│   │       │   └── ExportDecompiled.java
│   │       └── decompiled/
│   │           ├── 0001_function_name.c
│   │           └── 0002_function_name.c
│   │
│   └── WifiManager/
│       ├── analysis_summary.json
│       └── Generated_CSharp/
│           ├── Source/
│           │   └── ...
│           └── all_methods_il.txt
│
└── batch_summary.json
```

### Generated files

| File / Directory | Description |
|---|---|
| `analysis_summary.json` | DLL metadata, SHA-256, file size, and PE information |
| `processing_result.json` | Processing status, binary type, generated file counts, and errors |
| `Source/` | Decompiled C# source files |
| `all_methods_il.txt` | Exported .NET Intermediate Language |
| `functions.json` | Native function metadata and decompilation status |
| `functions.txt` | Human-readable function listing |
| `decompiled/` | Individual C-like pseudocode files |
| `ghidra_console.log` | Ghidra execution output and diagnostic information |
| `GhidraScripts/` | Java-based Ghidra export script |
| `batch_summary.json` | Overall batch processing results |

## Processing Status

| Status | Meaning |
|---|---|
| `SUCCESS` | Applicable analysis completed without recorded errors |
| `PARTIAL` | An analysis engine succeeded, but another operation reported an error |
| `FAILED` | No applicable analysis engine completed successfully |

The batch summary includes total DLLs processed and counts of successful, partially successful, and failed analyses.

## Technical Implementation

### PE inspection

The script uses Python's `struct` module to inspect PE headers and determine:

- DOS and PE signatures
- Machine architecture
- Optional header format
- PE sections
- CLR data directory
- CLR flags
- Managed versus native classification

### Managed analysis

ILSpy is invoked through its command-line interface to reconstruct C# source and export IL.

### Native analysis

Ghidra Headless Analyzer performs binary analysis and function decompilation.

To improve Windows path compatibility, the original DLL is copied into a short temporary workspace before Ghidra is launched. The generated Java Ghidra script exports function information and decompiled pseudocode. Results are then copied into the corresponding output directory.

## Limitations

- Decompilation does not guarantee recovery of original source code, variable names, comments, or project structure.
- Native decompiler output is reconstructed pseudocode, not original source code.
- Obfuscated, packed, corrupted, or unsupported binaries may produce incomplete results.
- Ghidra analysis time depends on DLL size, complexity, architecture, and available system resources.
- Some PE files may contain malformed or unusual headers that affect classification or analysis.
- Mixed-mode DLLs are processed using both applicable analysis engines, but results may be incomplete.
- This tool currently targets Windows DLL files and uses Windows-specific Ghidra headless execution.

## Legal and Ethical Use

This project is intended for authorised reverse engineering, malware analysis, software interoperability research, digital forensics, security auditing, and educational purposes.

Only analyse DLLs that you own or are legally authorised to examine. Respect applicable software licences, intellectual property rights, and local laws.

## Dependencies

| Component | Purpose | Licence |
|---|---|---|
| Python | Automation and PE inspection | PSF |
| ILSpy | .NET decompilation | MIT |
| Ghidra | Native binary analysis and decompilation | Apache 2.0 |

Refer to the respective projects for their licence terms.

## Contributing

Contributions, bug reports, feature requests, and improvements are welcome.

1. Fork the repository.
2. Create a feature branch.
3. Commit your changes.
4. Submit a pull request.

## Disclaimer

REA is provided for research and educational purposes. The authors are not responsible for misuse, unauthorised analysis, or damage resulting from use of this software.

## Author

**codarabbit**

GitHub: [https://github.com/codarabbit](https://github.com/codarabbit)

---

*Built by codarabbit — automating DLL reverse engineering with Python, ILSpy, and Ghidra.*

