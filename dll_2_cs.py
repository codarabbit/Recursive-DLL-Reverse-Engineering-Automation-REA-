import argparse
import hashlib
import json
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path


GHIDRA_DEFAULT = r"C:\re\GHIDRA\support\analyzeHeadless.bat"


# ---------------------------------------------------------
# Tool detection
# ---------------------------------------------------------

def check_ilspy():
    exe = shutil.which("ilspycmd")
    if not exe:
        raise RuntimeError(
            "ilspycmd not found. Install using:\n"
            "dotnet tool install --global ilspycmd"
        )
    return exe


def check_ghidra(path):
    exe = Path(path)

    if not exe.is_file():
        raise RuntimeError(
            f"Ghidra headless launcher not found: {exe}\n"
            "Expected: C:\\re\\GHIDRA\\support\\analyzeHeadless.bat"
        )

    return str(exe)


def check_temp_base(path):
    """Validate the local temp base directory (None = system temp)."""
    if not path:
        return None

    base = Path(path).resolve()
    base.mkdir(parents=True, exist_ok=True)
    return base


# ---------------------------------------------------------
# File utilities
# ---------------------------------------------------------

def sha256_file(path):
    digest = hashlib.sha256()

    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=4, ensure_ascii=False),
        encoding="utf-8"
    )


def safe_filename(name):
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name)
    return name[:120] or "unnamed_function"


def run_command(command, timeout=1800):
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=timeout
    )


# ---------------------------------------------------------
# PE / CLR detection
# No third-party Python package required.
# ---------------------------------------------------------

def inspect_pe(path):
    result = {
        "valid_pe": False,
        "architecture": "Unknown",
        "managed": False,
        "mixed_mode": False,
        "binary_type": "INVALID_OR_UNKNOWN",
        "clr_flags": None,
        "sections": []
    }

    try:
        data = path.read_bytes()

        if data[:2] != b"MZ":
            return result

        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]

        if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
            return result

        coff = pe_offset + 4

        machine, section_count = struct.unpack_from("<HH", data, coff)
        optional_size = struct.unpack_from("<H", data, coff + 16)[0]

        optional = coff + 20
        magic = struct.unpack_from("<H", data, optional)[0]

        architectures = {
            0x014c: "x86",
            0x8664: "x64",
            0x01c0: "ARM",
            0x01c4: "ARMv7",
            0xAA64: "ARM64"
        }

        result["architecture"] = architectures.get(
            machine, hex(machine)
        )

        if magic == 0x10B:
            directory_offset = optional + 96
        elif magic == 0x20B:
            directory_offset = optional + 112
        else:
            return result

        number_of_directories_offset = (
            optional + (92 if magic == 0x10B else 108)
        )

        directory_count = struct.unpack_from(
            "<I", data, number_of_directories_offset
        )[0]

        section_table = optional + optional_size

        sections = []

        for index in range(section_count):
            offset = section_table + (index * 40)

            name = data[offset:offset + 8].split(b"\x00")[0]
            virtual_size, virtual_address, raw_size, raw_offset = (
                struct.unpack_from("<IIII", data, offset + 8)
            )

            sections.append({
                "name": name.decode("ascii", errors="replace"),
                "virtual_address": virtual_address,
                "virtual_size": virtual_size,
                "raw_offset": raw_offset,
                "raw_size": raw_size
            })

        result["sections"] = sections
        result["valid_pe"] = True

        if directory_count <= 14:
            result["binary_type"] = "NATIVE"
            return result

        # IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14
        clr_entry = directory_offset + (14 * 8)

        clr_rva, clr_size = struct.unpack_from(
            "<II", data, clr_entry
        )

        if not clr_rva or not clr_size:
            result["binary_type"] = "NATIVE"
            return result

        clr_offset = None

        for section in sections:
            start = section["virtual_address"]
            end = start + max(
                section["virtual_size"],
                section["raw_size"]
            )

            if start <= clr_rva < end:
                clr_offset = (
                    section["raw_offset"] + clr_rva - start
                )
                break

        if clr_offset is None:
            result["binary_type"] = "CLR_HEADER_UNRESOLVED"
            return result

        # IMAGE_COR20_HEADER.Flags is at offset 16.
        clr_flags = struct.unpack_from(
            "<I", data, clr_offset + 16
        )[0]

        # COMIMAGE_FLAGS_ILONLY = 0x1
        il_only = bool(clr_flags & 0x1)

        result["managed"] = True
        result["clr_flags"] = hex(clr_flags)

        if il_only:
            result["binary_type"] = "MANAGED_DOTNET"
        else:
            result["mixed_mode"] = True
            result["binary_type"] = "MIXED_MODE"

        return result

    except Exception as e:
        result["inspection_error"] = str(e)
        return result


# ---------------------------------------------------------
# Existing REA analysis files
# ---------------------------------------------------------

def load_analysis(analysis_dir):
    info = {}
    members = {}

    for filename, target in [
        ("managed-info.json", "info"),
        ("managed-members.json", "members")
    ]:
        file_path = analysis_dir / filename

        if not file_path.exists():
            continue

        try:
            content = json.loads(
                file_path.read_text(encoding="utf-8-sig")
            )

            if target == "info":
                info = content
            else:
                members = content

        except Exception as e:
            print(f"[!] Could not read {filename}: {e}")

    return info, members


# ---------------------------------------------------------
# ILSpy: managed DLLs
# ---------------------------------------------------------

def decompile_managed(dll, output_dir, ilspy):
    source_dir = output_dir / "Source"
    source_dir.mkdir(parents=True, exist_ok=True)

    command = [
        ilspy,
        "-p",
        "-o",
        str(source_dir),
        str(dll)
    ]

    print("[+] ILSpy decompilation:", dll.name)

    result = run_command(command)

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr or result.stdout or
            "ILSpy decompilation failed"
        )

    cs_files = list(source_dir.rglob("*.cs"))

    print(f"[+] C# files generated: {len(cs_files)}")

    return len(cs_files)


def export_il(dll, output_dir, ilspy):
    il_file = output_dir / "all_methods_il.txt"

    result = run_command([
        ilspy,
        "-il",
        str(dll)
    ])

    if result.returncode == 0:
        il_file.write_text(result.stdout, encoding="utf-8")
        print("[+] IL exported")
        return True

    print("[!] IL export failed:", result.stderr)
    return False


# ---------------------------------------------------------
# Ghidra decompiler script
# ---------------------------------------------------------

GHIDRA_SCRIPT = r'''
//@category BatchReverseEngineering

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class ExportDecompiled extends GhidraScript {

    private static String safe(String v) {
        String s = v.replaceAll("[^A-Za-z0-9_.-]+", "_");
        if (s.length() > 120) s = s.substring(0, 120);
        return s.isEmpty() ? "unnamed" : s;
    }

    private static String q(String s) {
        if (s == null) return "null";
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"':  b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.append('"').toString();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length == 0) {
            throw new IllegalArgumentException("Output directory argument missing");
        }

        Path out = Paths.get(args[0]);
        Path pseudo = out.resolve("decompiled");
        Files.createDirectories(pseudo);

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        StringBuilder json = new StringBuilder("[\n");
        StringBuilder txt = new StringBuilder();
        int index = 0;
        boolean first = true;

        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (monitor.isCancelled()) break;
            index++;

            String name = f.getName();
            String entry = f.getEntryPoint().toString();
            String file = null;
            boolean ok = false;
            String error = null;

            if (!f.isExternal()) {
                try {
                    DecompileResults r = decomp.decompileFunction(f, 120, monitor);
                    if (r.decompileCompleted()) {
                        String fn = String.format("%04d_%s.c", index, safe(name));
                        Files.write(pseudo.resolve(fn),
                            r.getDecompiledFunction().getC().getBytes(StandardCharsets.UTF_8));
                        file = fn;
                        ok = true;
                    } else {
                        error = r.getErrorMessage();
                    }
                } catch (Exception e) {
                    error = e.toString();
                }
            }

            if (!first) json.append(",\n");
            first = false;
            json.append("    {")
                .append("\"name\": ").append(q(name)).append(", ")
                .append("\"entry_point\": ").append(q(entry)).append(", ")
                .append("\"namespace\": ").append(q(f.getParentNamespace().toString())).append(", ")
                .append("\"is_external\": ").append(f.isExternal()).append(", ")
                .append("\"is_thunk\": ").append(f.isThunk()).append(", ")
                .append("\"file\": ").append(q(file)).append(", ")
                .append("\"decompiled\": ").append(ok).append(", ")
                .append("\"error\": ").append(q(error))
                .append("}");

            txt.append(entry).append("  ").append(name)
               .append("  decompiled=").append(ok ? "True" : "False").append("\n");
        }
        json.append("\n]\n");
        decomp.dispose();

        Files.write(out.resolve("functions.json"), json.toString().getBytes(StandardCharsets.UTF_8));
        Files.write(out.resolve("functions.txt"), txt.toString().getBytes(StandardCharsets.UTF_8));
        println("Exported " + index + " function records");
    }
}
'''

def run_ghidra(dll, output_dir, ghidra, temp_base=None, keep_temp=False):
    """
    Run Ghidra headless entirely inside a short, local temp folder.

    Layout of the temp folder:
        <temp>/input/<dll>        copy of the DLL being analysed
        <temp>/project/           Ghidra project (deleted by Ghidra too)
        <temp>/scripts/           ExportDecompiled.py
        <temp>/out/               decompiled/, functions.json, ...
        <temp>/run_ghidra.cmd     launcher

    When Ghidra finishes, <temp>/out is copied into output_dir and the
    temp folder is removed (unless keep_temp is True).
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    temp_root = Path(
        tempfile.mkdtemp(
            prefix="rea_",
            dir=str(temp_base) if temp_base else None
        )
    )

    print("[+] Ghidra temp folder:", temp_root)

    temp_input = temp_root / "input"
    temp_project = temp_root / "project"
    temp_scripts = temp_root / "scripts"
    temp_out = temp_root / "out"

    for folder in (temp_input, temp_project, temp_scripts, temp_out):
        folder.mkdir(parents=True, exist_ok=True)

    local_dll = temp_input / dll.name
    shutil.copy2(dll, local_dll)

    script_file = temp_scripts / "ExportDecompiled.java"
    script_file.write_text(GHIDRA_SCRIPT, encoding="utf-8")

    project_name = safe_filename(dll.stem)[:40] + "_Analysis"

    launcher = temp_root / "run_ghidra.cmd"

    def cmd_quote(value):
        # Double quotes protect spaces and parentheses.
        return '"' + str(value).replace('"', '""') + '"'

    lines = [
        "@echo off",
        "setlocal",
        f"call {cmd_quote(ghidra)} "
        f"{cmd_quote(temp_project)} "
        f"{cmd_quote(project_name)} "
        f"-scriptPath {cmd_quote(temp_scripts)} "
        f"-import {cmd_quote(local_dll)} "
        f"-postScript ExportDecompiled.java {cmd_quote(temp_out)} "
        "-deleteProject",
        "exit /b %ERRORLEVEL%"
    ]

    launcher.write_text("\r\n".join(lines) + "\r\n", encoding="utf-8")

    log_file = output_dir / "ghidra_console.log"

    try:
        result = subprocess.run(
            ["cmd.exe", "/d", "/c", str(launcher)],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=3600
        )

        # The log goes straight to the final output folder so it is
        # available even when the run fails and temp is wiped.
        log = (
            "TEMP FOLDER: " + str(temp_root) + "\n"
            "ORIGINAL DLL: " + str(dll) + "\n\n"
            "LAUNCHER:\n" + "\n".join(lines) +
            "\n\nSTDOUT:\n" + (result.stdout or "") +
            "\n\nSTDERR:\n" + (result.stderr or "")
        )

        log_file.write_text(log, encoding="utf-8")

        if result.returncode != 0:
            raise RuntimeError(
                f"Ghidra exited with code {result.returncode}. "
                "Check ghidra_console.log"
            )

        functions_file = temp_out / "functions.json"

        if not functions_file.exists():
            raise RuntimeError(
                "Ghidra finished but functions.json was not generated. "
                "Check ghidra_console.log."
            )

        functions = json.loads(
            functions_file.read_text(encoding="utf-8")
        )

        total = len(functions)
        decompiled = sum(
            1 for item in functions if item.get("decompiled")
        )

        # Copy results from the local temp folder to the real output.
        print("[+] Copying Ghidra results to:", output_dir)

        shutil.copytree(
            temp_out,
            output_dir,
            dirs_exist_ok=True
        )

        # Keep a copy of the export script next to the results.
        script_copy_dir = output_dir / "GhidraScripts"
        script_copy_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(script_file, script_copy_dir / script_file.name)

        print(
            f"[+] Ghidra functions: {total} "
            f"| Decompiled: {decompiled}"
        )

        return total, decompiled

    finally:
        if keep_temp:
            print("[+] Temp folder kept:", temp_root)
        else:
            shutil.rmtree(temp_root, ignore_errors=True)


# ---------------------------------------------------------
# Per-DLL report
# ---------------------------------------------------------

def generate_report(
    dll,
    pe_info,
    info,
    members,
    output_dir
):
    data = {
        "dll": dll.name,
        "dll_path": str(dll),
        "sha256": sha256_file(dll),
        "file_size": dll.stat().st_size,
        "pe_information": pe_info,
        "managed_info": info,
        "managed_members": members
    }

    write_json(output_dir / "analysis_summary.json", data)


# ---------------------------------------------------------
# Process one DLL
# ---------------------------------------------------------

def process_dll(
    dll,
    root_dir,
    output_root,
    ilspy,
    ghidra,
    temp_base=None,
    keep_temp=False
):
    relative_path = dll.relative_to(root_dir)

    dll_output = (
        output_root / relative_path.parent / dll.stem
    )

    dll_output.mkdir(parents=True, exist_ok=True)

    print("\n" + "=" * 70)
    print("[DLL]", dll)
    print("[OUT]", dll_output)
    print("=" * 70)

    result = {
        "dll": str(dll),
        "status": "FAILED",
        "binary_type": "UNKNOWN",
        "csharp_files": 0,
        "native_functions": 0,
        "native_decompiled_functions": 0,
        "output": str(dll_output),
        "errors": []
    }

    try:
        pe_info = inspect_pe(dll)
        binary_type = pe_info["binary_type"]

        result["binary_type"] = binary_type

        print("[+] Binary type:", binary_type)
        print("[+] Architecture:", pe_info["architecture"])

        analysis_candidates = [
            dll.parent,
            dll.parent / "DLL_Analysis",
            dll.parent / f"{dll.stem}_Analysis"
        ]

        analysis_dir = next(
            (
                p for p in analysis_candidates
                if (p / "managed-info.json").exists()
                or (p / "managed-members.json").exists()
            ),
            dll.parent
        )

        info, members = load_analysis(analysis_dir)

        generate_report(
            dll,
            pe_info,
            info,
            members,
            dll_output
        )

        managed_success = False
        native_success = False

        # Managed .NET or mixed-mode: ILSpy
        if binary_type in ("MANAGED_DOTNET", "MIXED_MODE"):

            csharp_output = dll_output / "Generated_CSharp"
            csharp_output.mkdir(parents=True, exist_ok=True)

            try:
                result["csharp_files"] = decompile_managed(
                    dll, csharp_output, ilspy
                )

                export_il(dll, csharp_output, ilspy)
                managed_success = True

            except Exception as e:
                result["errors"].append(
                    "ILSpy: " + str(e)
                )
                print("[ERROR] ILSpy:", e)

        # Native or mixed-mode: Ghidra (runs in a local temp folder)
        if binary_type in (
            "NATIVE",
            "MIXED_MODE",
            "CLR_HEADER_UNRESOLVED"
        ):

            native_output = dll_output / "Generated_Native"
            native_output.mkdir(parents=True, exist_ok=True)

            try:
                total, decompiled = run_ghidra(
                    dll,
                    native_output,
                    ghidra,
                    temp_base=temp_base,
                    keep_temp=keep_temp
                )

                result["native_functions"] = total
                result["native_decompiled_functions"] = decompiled
                native_success = True

            except Exception as e:
                result["errors"].append(
                    "Ghidra: " + str(e)
                )
                print("[ERROR] Ghidra:", e)

        if binary_type == "INVALID_OR_UNKNOWN":
            result["errors"].append(
                "Could not identify a valid PE binary"
            )

        if managed_success or native_success:
            if result["errors"]:
                result["status"] = "PARTIAL"
            else:
                result["status"] = "SUCCESS"

        write_json(
            dll_output / "processing_result.json",
            result
        )

    except Exception as e:
        result["errors"].append(str(e))
        print(f"[ERROR] {dll.name}: {e}")

        write_json(
            dll_output / "processing_result.json",
            result
        )

    return result


# ---------------------------------------------------------
# Main recursive batch processor
# ---------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Recursive managed and native DLL reverse engineering "
            "using ILSpy and Ghidra"
        )
    )

    parser.add_argument(
        "--input",
        required=True,
        help="Root folder containing DLL files"
    )

    parser.add_argument(
        "--output",
        required=True,
        help="Output root folder"
    )

    parser.add_argument(
        "--ghidra",
        default=GHIDRA_DEFAULT,
        help="Path to Ghidra analyzeHeadless.bat"
    )

    parser.add_argument(
        "--temp-dir",
        default=None,
        help=(
            "Local folder used as the base for native (Ghidra) work "
            "folders, e.g. C:\\re\\tmp. Defaults to the system temp "
            "folder. Keep it short and local."
        )
    )

    parser.add_argument(
        "--keep-temp",
        action="store_true",
        help="Do not delete the temp work folders after Ghidra runs"
    )

    args = parser.parse_args()

    root_dir = Path(args.input).resolve()
    output_root = Path(args.output).resolve()

    if not root_dir.is_dir():
        sys.exit("[-] Input directory does not exist")

    output_root.mkdir(parents=True, exist_ok=True)

    ilspy = check_ilspy()
    ghidra = check_ghidra(args.ghidra)
    temp_base = check_temp_base(args.temp_dir)

    print("[+] ILSpy:", ilspy)
    print("[+] Ghidra:", ghidra)
    print("[+] Temp base:", temp_base or tempfile.gettempdir())

    dll_files = sorted(
        p for p in root_dir.rglob("*")
        if p.is_file()
        and p.suffix.lower() == ".dll"
        and output_root not in p.parents
        and p.parent != output_root
    )

    if not dll_files:
        sys.exit("[-] No DLL files found")

    print("\n" + "=" * 70)
    print("       RECURSIVE DLL REVERSE ENGINEERING")
    print("=" * 70)
    print("[+] Input:", root_dir)
    print("[+] Output:", output_root)
    print("[+] DLL count:", len(dll_files))

    results = []

    for index, dll in enumerate(dll_files, start=1):
        print(
            f"\n[{index}/{len(dll_files)}] "
            f"Processing {dll.name}"
        )

        result = process_dll(
            dll,
            root_dir,
            output_root,
            ilspy,
            ghidra,
            temp_base=temp_base,
            keep_temp=args.keep_temp
        )

        results.append(result)

    success = sum(
        1 for r in results if r["status"] == "SUCCESS"
    )

    partial = sum(
        1 for r in results if r["status"] == "PARTIAL"
    )

    failed = sum(
        1 for r in results if r["status"] == "FAILED"
    )

    summary = {
        "input_directory": str(root_dir),
        "output_directory": str(output_root),
        "total_dlls": len(results),
        "successful": success,
        "partial": partial,
        "failed": failed,
        "results": results
    }

    summary_file = output_root / "batch_summary.json"
    write_json(summary_file, summary)

    print("\n" + "=" * 70)
    print("             BATCH PROCESSING COMPLETE")
    print("=" * 70)
    print("[+] Total DLLs:", len(results))
    print("[+] Successful:", success)
    print("[!] Partial:", partial)
    print("[-] Failed:", failed)
    print("[+] Summary:", summary_file)


if __name__ == "__main__":
    main()
