# DLL Reverse-Engineering Batch Pipeline (`rea_batch_v2.py`)

Recursively analyses every `.dll` under a folder using **ILSpy** (managed .NET)
and **Ghidra** (native), and produces decompiled source, deep PE metadata, a
searchable function inventory, and dependency / call graphs. Runs are
**incremental and resumable**, so a 1,000+ DLL job can be stopped and restarted.

## Requirements

| Tool | Needed for | Notes |
|---|---|---|
| Python 3.9+ | everything | standard library only, no pip packages |
| `ilspycmd` | managed / mixed-mode DLLs | `dotnet tool install --global ilspycmd` |
| Ghidra (headless) | native / mixed-mode DLLs | default path `C:\re\GHIDRA\support\analyzeHeadless.bat`, override with `--ghidra` |
| Graphviz (optional) | `--svg` | `dot` must be on `PATH` |

## Quick start

```powershell
# Try a few DLLs first
python rea_batch_v2.py --input "C:\path\to\dlls" --output C:\re\out --temp-dir C:\re\tmp --filter "*Name*" --debug

# Full run (safe to stop with Ctrl+C and re-run: it resumes)
python rea_batch_v2.py --input "C:\path\to\dlls" --output C:\re\out --temp-dir C:\re\tmp

# Progress and failure report
python rea_batch_v2.py --input "C:\path\to\dlls" --output C:\re\out --status

# Retry only what failed
python rea_batch_v2.py --input "C:\path\to\dlls" --output C:\re\out --temp-dir C:\re\tmp --only-failed
```

Notes:
- `--output` must be on a drive that exists. The folder is created if missing.
- Use a short, local `--temp-dir` (for example `C:\re\tmp`). Ghidra struggles with
  long paths and network drives.
- Output for ~1,000 DLLs can reach several GB, including a copy of every original DLL.

## What it does per DLL

1. Hashes the file (SHA-256) and compares it with the manifest.
2. Skips it if it is unchanged and already complete.
3. Parses the PE structure (pure Python) and writes `pe_metadata.json`.
4. Copies the original DLL to `Original/` (SHA-256 verified).
5. Decompiles with ILSpy (.NET) and/or Ghidra (native), depending on the binary type.
6. Writes a summary, graphs, and indexes the DLL into `inventory.db`.

| Binary type | Tool used |
|---|---|
| `MANAGED_DOTNET` | ILSpy |
| `MIXED_MODE` | ILSpy and Ghidra |
| `NATIVE`, `CLR_HEADER_UNRESOLVED` | Ghidra |
| `INVALID_OR_UNKNOWN` | none, recorded as `INVALID_BINARY` |

## Output layout

```
<output>\
  manifest.db              resume state: SHA-256, per-stage status, tool versions, errors
  inventory.db             searchable SQLite index (see "Searching")
  events.jsonl             structured event log (one JSON object per line)
  batch.log                full text log
  batch_summary.json       totals and per-DLL results for the latest run
  graphs\dll_dependencies.dot   DLL-to-DLL dependency graph for the whole set
  <relative folder>\<dll name>\
      Original\<dll>                copy of the source DLL
      pe_metadata.json              full PE metadata (see below)
      analysis_summary.json         compact summary
      processing_result.json        status, stages, errors, warnings
      Logs\pipeline.log  ilspy.log  ghidra.log
      Generated_CSharp\Source\*.cs  all_methods_il.txt
      Generated_Native\decompiled\*.c
                       functions.json  functions.txt  function_inventory.csv  program.json
      Graphs\dependencies.dot  imports.dot  call_graph.dot  api_calls.dot
             entry_paths.dot  entry_paths.json   (+ .svg with --svg)
```

### PE metadata (`pe_metadata.json`)

Architecture, image base, entry point (and its section), timestamp, subsystem,
linker/OS versions, DLL characteristics (ASLR, DEP, CFG, etc.), sections with
entropy, overlay size, Authenticode presence, exports (including forwarders),
imports and delay-imports, imported DLL dependencies, imphash, API categories
(triage keyword lists, not verdicts), debug directory (PDB path, GUID, age),
TLS callbacks, resource inventory, embedded manifest, version-info strings, and
.NET CLR header details.

### Function intelligence (native DLLs)

For each function: name, address, namespace, signature, calling convention,
parameters, return type, size, basic-block count, CFG edges, cyclomatic complexity
estimate (edges - blocks + 2), cross-references, callers, callees, external API
calls, whether it is a thunk or entry point, and the decompiled C file. Written
to `functions.json` and `function_inventory.csv`.

### Graphs

| File | Shows |
|---|---|
| `dependencies.dot` | the DLL and the DLLs it imports (dashed = delay-load, blue = also in your input set) |
| `imports.dot` | DLL, imported library, API (suspicious API categories highlighted) |
| `call_graph.dot` | function-to-function calls (entry points green, API-calling functions red) |
| `api_calls.dot` | functions, imported APIs grouped by library |
| `entry_paths.dot/.json` | shortest paths from entry points to APIs |

Large graphs are truncated to `--graph-max-nodes` and labelled as truncated.
For the global graph on huge sets, render with `sfdp -Tsvg`.

## Searching (`inventory.db`)

Open with any SQLite tool or Python's `sqlite3`.

```sql
-- Which DLLs call CreateRemoteThread?
SELECT DISTINCT d.name FROM api_calls a JOIN dlls d ON d.id = a.dll_id
WHERE a.api = 'CreateRemoteThread';

-- Functions by name or signature (full-text)
SELECT f.name, f.signature, d.name FROM functions f JOIN dlls d ON d.id = f.dll_id
WHERE f.id IN (SELECT rowid FROM functions_fts WHERE functions_fts MATCH 'decrypt');

-- Most complex functions
SELECT d.name, f.name, f.complexity FROM functions f JOIN dlls d ON d.id = f.dll_id
ORDER BY f.complexity DESC LIMIT 20;

-- DLLs sharing the same imphash
SELECT imphash, GROUP_CONCAT(name) FROM dlls GROUP BY imphash HAVING COUNT(*) > 1;
```

Tables: `dlls`, `exports`, `imports`, `dependencies`, `functions`, `api_calls`
(plus `functions_fts`). Rebuild from existing outputs with `--reindex`.

## Resume, retries and failure handling

- **Resume:** state is saved after every DLL. After Ctrl+C or a crash, re-run
  the same command. Completed work is skipped, and each tool (ILSpy / Ghidra) is
  tracked separately, so a successful stage is never repeated.
- **Changed files:** if a DLL's SHA-256 changes, it is reanalysed. Unchanged files
  are recognised by size and modified time without re-hashing (`--verify-hashes`
  forces re-hashing).
- **Retries:** retryable errors (timeouts, project locks, I/O errors) are retried
  `--retries` times (default 1) with doubling backoff. Timeouts grow by
  `--timeout-multiplier` each retry.
- **Error categories:** `TIMEOUT`, `OUT_OF_MEMORY`, `PROJECT_LOCK`, `INVALID_BINARY`,
  `SCRIPT_ERROR`, `IO_ERROR`, `TOOL_MISSING`, `OUTPUT_MISSING`, `UNKNOWN`.
  `INVALID_BINARY` is treated as permanent and skipped on later runs unless you pass
  `--retry-failed`.
- **Interrupt:** the first Ctrl+C stops the running tool safely and records
  `INTERRUPTED`. A second Ctrl+C force-quits.
- **Troubleshooting:** `--keep-failed-temp` (or `--debug`) preserves the Ghidra work
  folder of any failed run. Its path is recorded in the log and `events.jsonl`.
  Check `Logs\ghidra.log` in the DLL's output folder first.
- **Exit codes:** `0` all good, `1` at least one DLL failed this run, `130` interrupted.

## Options

| Option | Purpose |
|---|---|
| `--input`, `--output` | required folders |
| `--ghidra PATH` | Ghidra `analyzeHeadless` launcher |
| `--temp-dir PATH` | base folder for Ghidra work directories |
| `--filter GLOB` | only DLLs whose relative path matches (case-insensitive) |
| `--force` | reanalyse everything |
| `--only-failed` | only DLLs that failed or were interrupted |
| `--retry-failed` | also retry permanent failures |
| `--reanalyse-on-tool-change` | redo DLLs when ILSpy/Ghidra version differs from the recorded one |
| `--verify-hashes` | always re-hash files |
| `--reindex` | rebuild `inventory.db` from existing outputs |
| `--status` | print manifest status and exit |
| `--retries N`, `--retry-backoff S`, `--timeout-multiplier X` | retry policy |
| `--ilspy-timeout S`, `--ghidra-timeout S` | per-stage timeouts (defaults 1800 / 3600) |
| `--ghidra-analysis-timeout S` | pass `-analysisTimeoutPerFile` to Ghidra |
| `--no-decompile` | export function metadata only (much faster) |
| `--decompile-timeout S` | per-function decompile limit (default 120) |
| `--keep-temp` / `--keep-failed-temp` | keep all / failed Ghidra temp folders |
| `--debug` | verbose console output and `--keep-failed-temp` |
| `--no-copy-original` | do not copy the source DLL to `Original\` |
| `--no-graphs`, `--svg`, `--dot-engine`, `--graph-max-nodes`, `--graph-include-external` | graph controls |

## Known limitations

- Developed and tested on Linux with stand-in ILSpy/Ghidra programs. Run it on a
  handful of DLLs with real tools before a full batch. If the Ghidra export script
  fails to compile on your Ghidra version, the error appears in `Logs\ghidra.log`
  as `SCRIPT_ERROR`.
- Cyclomatic complexity is an estimate from Ghidra's basic-block graph.
- API categories (injection, network, crypto, and so on) are keyword lists for
  triage, not evidence of malicious behaviour.
- The imphash may differ from other tools for a few ordinal-only imports.
- Changing the Ghidra export script version triggers reanalysis of native DLLs.
- Output and analysis are derived from files you are authorised to examine.
  Check the software licence before decompiling or sharing results.
