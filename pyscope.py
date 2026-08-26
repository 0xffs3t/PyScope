# PyScope v0.3
# Python 3.14.7
# Ethan J. Wells
# 8/23/2026
# PyScope is an open-source recursive forensic file scanner developed as a learner project.
# Originally developed on MacOS, but with compatibility in mind.


# ------- IMPORT NECESSARY MODULES -------


import os
import sys
import pwd
import grp
import stat
import json
import time
import hashlib
import argparse
import itertools
import threading
from pathlib import Path
from typing import Optional
from datetime import datetime
from dataclasses import dataclass


# ------- DEFINE COLOR VARIABLES -------


W = '\033[0m'  # white (normal)
R = '\033[31m'  # red
G = '\033[32m'  # green
O = '\033[33m'  # orange
B = '\033[34m'  # blue
P = '\033[35m'  # purple
C = '\033[36m'  # cyan
GR = '\033[37m'  # gray


# ------- DEFINE SCRIPT DIRECORY & TIMESTAMP VARIABLES -------


script_dir = Path(__file__).parent.resolve()
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


# ------- ESTABLISH HASH VALIDATION CLASSES -------


@dataclass
class HashValidation:
    md5_match: bool
    sha256_match: bool
    expected_md5: str
    expected_sha256: str
    invalid_md5: Optional[str]
    invalid_sha256: Optional[str]


# ------- ESTABLISH FILE RESULT CLASSES -------


@dataclass
class FileResult:
    name: str
    path: Path
    size: int
    extension: str
    file_type: str
    signature: Optional[bytes]
    confidence: str
    owner: str
    group: str
    permissions: str
    flags: list[str]
    inode: int
    device: int
    link_count: int
    extension_mismatch: bool
    modified: datetime
    accessed: datetime
    created: datetime
    md5: str
    sha256: str


# ------- ESTABLISH SCAN RESULT CLASSES -------


@dataclass
class ScanResult:
    scan_path: str
    files_discovered: int
    files_analyzed: int
    files_failed: int
    total_size: int
    scan_error: list
    hard_link_groups: int
    files: list[FileResult]


# ------- ESTABLISH FILE SIGNATURE CLASSES -------


@dataclass
class FileSignature:
    signature: bytes
    file_type: str
    extensions: list[str]
    offset: int = 0
    confidence: str = "high"
    secondary_signature: bytes | None = None
    secondary_offset: int = 0


# ------- FILE SIGNATURE DATABASE -------


FILE_SIGNATURES = [
    FileSignature(
        signature=b"\x47\x49\x46\x38",
        file_type="GIF Image",
        extensions=[".gif"],
        confidence="high"
    ),

    FileSignature(
        signature=b"\xFF\xD8\xFF",
        file_type="JPEG Image",
        extensions=[".jpg", ".jpeg"],
        confidence="high"
    ),


    FileSignature(
        signature=b"\x89PNG\r\n\x1a\n",
        file_type="PNG Image",
        extensions=[".png"],
        confidence="high"
    ),

    FileSignature(
        signature=b"PK\x03\x04",
        file_type="ZIP Archive",
        extensions=[".zip"],
        confidence="medium"
    ),

    FileSignature(
        signature=b"MZ",
        file_type="Windows Executable",
        extensions=[".exe", ".dll"],
        confidence="high"
    ),

    FileSignature(
        signature=b"\x25\x50\x44\x46",
        file_type="PDF Document",
        extensions=[".pdf"],
        confidence="high"
    ),

    FileSignature(
        signature=b"RIFF",
        file_type="WAV Audio",
        extensions=[".wav"],
        offset=0,
        confidence="high",
        secondary_signature=b"WAVE",
        secondary_offset=8
    ),

    FileSignature(
        signature=b"ID3",
        file_type="MP3 Audio",
        extensions=[".mp3"],
        confidence="medium"
    ),

    FileSignature(
        signature=b"\x42\x4D",
        file_type="Bitmap Image",
        extensions=[".bmp"],
        confidence="high"
    ),

    FileSignature(
        signature=b"Rar!\x1A\x07\x01\x00",
        file_type="RAR Archive",
        extensions=[".rar"],
        confidence="high"
    ),

    FileSignature(
        signature=b"Rar!\x1A\x07\x00",
        file_type="RAR Archive",
        extensions=[".rar"],
        confidence="high"
    ),

    FileSignature(
        signature=b"\x1F\x8B",
        file_type="GZIP Archive",
        extensions=[".gz"],
        confidence="high"
    ),

    FileSignature(
        signature=b"7z\xBC\xAF\x27\x1C",
        file_type="7-Zip Archive",
        extensions=[".7z"],
        confidence="high"
    ),

    FileSignature(
        signature=b"\x7FELF",
        file_type="ELF Binary",
        extensions=["", ".elf"],
        confidence="high"
    )
]


# ------- DETERMINE IF PATH IS VALID FILE OR DIRECTORY -------

try:
    def analyze_path(path, recursive, verbose, log, compare):

        if path.is_file():
            result = run_loader(
                examine_file,
                path,
                show_loader=not verbose
            )

            if result and verbose:
                display_result(result)

            return

        if path.is_dir():
            scan_result = run_loader(
                scan_directory,
                path,
                recursive,
                verbose,
                show_loader=not verbose
            )

            process_scans(
                    scan_result,
                    verbose,
                    log,
                    compare
                )

            return

        print("File or directory not found.")


    # ------- DETECT OPERATING SYSTEM -------


    def detect_os():
        if sys.platform.startswith('win'):
            return "Windows"

        if sys.platform.startswith('darwin'):
            return "macOS"

        if sys.platform.startswith("linux"):
            return "Linux"
        else:
            return "Unknown"


    # ------- CLEAR SCREEN -------
    # this function is no longer used, for now at least


    def clear_screen():
        operating_system = detect_os()

        if operating_system == "Windows":
            os.system("cls")
        else:  # macOS and Linux
            os.system("clear")


    # ------- GET TIMESTAMPS -------


    def get_timestamps(file_info):
        operating_system = detect_os()

        modified_time = datetime.fromtimestamp(file_info.st_mtime)
        accessed_time = datetime.fromtimestamp(file_info.st_atime)

        if operating_system == "Windows":
            created_time = datetime.fromtimestamp(file_info.st_ctime)

        elif operating_system == "macOS":
            created_time = datetime.fromtimestamp(file_info.st_birthtime)

        elif operating_system == "Linux":
            if hasattr(file_info, "st_birthtime"):
                created_time = datetime.fromtimestamp(file_info.st_birthtime)
            else:
                created_time = datetime.fromtimestamp(file_info.st_ctime)
        else:
            created_time = datetime.fromtimestamp(file_info.st_ctime)

        return modified_time, accessed_time, created_time


    # ------- GET FILE FLAGS -------


    def get_flags(file_info) -> list[str]:
        flags = []

        if file_info.st_flags & stat.UF_HIDDEN:
            flags.append("hidden")

        if file_info.st_flags & stat.UF_IMMUTABLE:
            flags.append("immutable")

        if file_info.st_flags & stat.UF_APPEND:
            flags.append("append-only")

        if file_info.st_flags & stat.UF_NOUNLINK:
            flags.append("undeletable")

        return flags


    # ------- GET FILE PERMISSIONS -------


    def get_permissions(file_info):
        return stat.filemode(file_info.st_mode)


    # -------  GET UID & GID -------


    def get_ownership(file_info):
        operating_system = detect_os()
        
        if operating_system == "Windows":
            return "Unavailable", "Unavailable"

        try:
            username = pwd.getpwuid(file_info.st_uid).pw_name
        except KeyError:
            username = "Unknown"

        try:
            groupname = grp.getgrgid(file_info.st_gid).gr_name
        except KeyError:
            groupname = "Unknwown"

        return username, groupname


    # ------- VALIDATE FILE EXTENSIONS -------


    def check_extension(file_extension, file_signature):
        if file_signature is None:
            return False

        return file_extension.lower() not in file_signature.extensions


    # ------- DETECT FILE TYPE -------


    def detect_file_type(file_path):
        with open(file_path, "rb") as file:
            header = file.read(32)

        for file_signature in FILE_SIGNATURES:
            start = file_signature.offset
            end = start + len(file_signature.signature)

            if header[start:end] != file_signature.signature:
                continue

            if file_signature.secondary_signature is not None:
                secondary_start = file_signature.secondary_offset
                secondary_end = (
                    secondary_start
                    + len(file_signature.secondary_signature)
                )

                if header[secondary_start:secondary_end] != file_signature.secondary_signature:
                    continue

            return file_signature

        return None


    # ------- RUN PROCESS WITH LOAD EFFECT -------


    def run_loader(function, *args, show_loader=False):

        if not show_loader:
            return function(*args)


        stop_loading_thread = threading.Event()

        loader_thread = threading.Thread(
            target=load_effect,
            args=(stop_loading_thread, args[0] if args else "")
        )

        loader_thread.start()

        try:
            return function(*args)
        finally:
            stop_loading_thread.set()
            loader_thread.join()


    # ------- RETRIEVE FILE METADATA -------


    def examine_file(input_path):
        file = Path(input_path)

        if not file.exists():
            print(R + 'File does not exist.')
            return

        if not file.is_file():
            print(R + 'The path is not a file.')
            return

        file_info = file.stat()

        inode = file_info.st_ino
        device = file_info.st_dev
        link_count = file_info.st_nlink

        flags = get_flags(file_info)

        owner, group = get_ownership(file_info)

        permissions = get_permissions(file_info)

        modified_time, accessed_time, created_time = get_timestamps(file_info)

        file_signature = detect_file_type(file)

        if file_signature:
            file_type = file_signature.file_type
            confidence = file_signature.confidence
            matched_signature = file_signature.signature

        else:
            file_type = "Unknown / Unrecognized"
            confidence = "none"
            matched_signature = None

        extension_mismatch = check_extension(file.suffix, file_signature)

        hashes = calculate_hash(file)
        md5_hash = hashes["md5"]
        sha256_hash = hashes["sha256"]

        return FileResult(
            name=file.name,
            path=file.resolve(),
            size=file_info.st_size,
            extension=file.suffix,
            file_type=file_type,
            signature=matched_signature,
            confidence=confidence,
            owner=owner,
            group=group,
            permissions=permissions,
            flags=flags,
            inode=inode,
            device=device,
            link_count=link_count,
            extension_mismatch=extension_mismatch,
            modified=modified_time,
            accessed=accessed_time,
            created=created_time,
            md5=md5_hash,
            sha256=sha256_hash
        )


    # ------- SCAN DIRECTORY -------


    def scan_directory(dir_path, recursive, verbose):
        directory = Path(dir_path)

        files_discovered = 0
        files_analyzed = 0
        files_failed = 0
        total_size = 0

        scan_errors = []

        file_identities = {}

        file_results = []

        if recursive:
            paths = directory.rglob("*")
        else:
            paths = directory.iterdir()

        for path in paths:
            try:
                if path.is_file():
                    files_discovered += 1
                    result = examine_file(path)

                    if result:
                        files_analyzed += 1
                        total_size += result.size
                        file_results.append(result)
                        if verbose:
                            display_result(result)

                        file_id = (result.device, result.inode)

                        if file_id in file_identities:
                            file_identities[file_id].append(result.path)
                        else:
                            file_identities[file_id] = [result.path]

            except OSError as error:
                files_failed += 1
                print(R + f'Could not analyze {path}: {error}' + W)

                scan_errors.append({
                    "path": str(path),
                    "error_type": type(error).__name__,
                    "error": str(error)
                })

        hard_link_groups = 0

        for file_id, paths in file_identities.items():
            if len(paths) > 1:
                hard_link_groups += 1

                if verbose:
                    print()
                    print(O + 'Hard Link Group Detected:' + W)

                    for path in paths:
                        print(' ' + str(path))

        return ScanResult(
            scan_path=str(directory.resolve()),
            files_discovered=files_discovered,
            files_analyzed=files_analyzed,
            files_failed=files_failed,
            total_size=total_size,
            scan_error=scan_errors,
            hard_link_groups=hard_link_groups,
            files=file_results
        )


    # ------- SCAN FILE PATTERN -------


    def scan_pattern(pattern, recursive, verbose):
        pattern_path = Path(pattern)

        if recursive:
            matches = pattern_path.parent.rglob(pattern_path.name)
        else:
            matches = pattern_path.parent.glob(pattern_path.name)


        files_discovered = 0
        files_analyzed = 0
        files_failed = 0
        total_size = 0

        scan_errors = []
        file_results = []
        file_identities = {}

        for path in matches:
            try:
                if path.is_file():
                    files_discovered += 1

                    result = examine_file(path)

                    if result:
                        files_analyzed += 1
                        total_size += result.size
                        file_results.append(result)

                        if verbose:
                            display_result(result)

                        file_id = (result.device, result.inode)

                        if file_id in file_identities:
                            file_identities[file_id].append(result.path)
                        else:
                            file_identities[file_id] = [result.path]
            except OSError as error:
                files_failed += 1
                print(R + f'Could not analyze {path}: {error}' + W)

                scan_errors.append({
                    "path": str(path),
                    "error_type": type(error).__name__,
                    "error": str(error)
                })

        hard_link_groups = 0

        for file_id, paths in file_identities.items():
            if len(paths) > 1:
                hard_link_groups += 1

        scan_result = ScanResult(
            scan_path=str(pattern_path),
            files_discovered=files_discovered,
            files_analyzed=files_analyzed,
            files_failed=files_failed,
            total_size=total_size,
            scan_error=scan_errors,
            hard_link_groups=hard_link_groups,
            files=file_results
        )

        if verbose:
            display_scan_result(scan_result)

        return scan_result


    # ------- ANALYZE PATTERN --------

    def analyze_pattern(pattern, recursive, verbose, log, compare):

        scan_result = run_loader(
            scan_pattern,
            pattern,
            recursive,
            verbose,
            show_loader=not verbose
        )

        changes = []

        process_scans(
                scan_result,
                verbose,
                log,
                compare
            )


    # ------- PROCESS SCANS --------


    def process_scans(scan_result, verbose, log, compare):
        previous_scan = None
        changes = []

        if compare:
            previous_scan = load_scan(compare)

        if previous_scan:
            changes = validate_scan(
                scan_result,
                previous_scan,
                verbose,
                log
            )

        if log:
            save_scan(scan_result, log)

        if changes and log:
            save_changes(changes, log)

        if verbose:
            display_scan_result(scan_result)

        return changes


    # ------- SAVE SCAN TO MANIFEST -------


    def save_scan(scan_result, log_path):
        output_path = Path(log_path)
        temp_path = output_path.with_suffix(output_path.suffix + ".tmp")

        data = {
            "pyscope_version": "0.3",
            "scan_path": scan_result.scan_path,
            "scan_time": datetime.now().isoformat(),
            "scan_errors": scan_result.scan_error,
            "files": []
        }

        for result in scan_result.files:
            data["files"].append({
                "name": result.name,
                "path": str(result.path),
                "size": result.size,
                "extension": result.extension,
                "file_type": result.file_type,
                "signature": result.signature.hex(" ") if result.signature else None,
                "confidence": result.confidence,
                "owner": result.owner,
                "group": result.group,
                "permissions": result.permissions,
                "flags": result.flags,
                "inode": result.inode,
                "device": result.device,
                "link_count": result.link_count,
                "extension_mismatch": result.extension_mismatch,
                "modified": result.modified.isoformat(),
                "accessed": result.accessed.isoformat(),
                "created": result.created.isoformat(),
                "md5": result.md5,
                "sha256": result.sha256,
            })

        with open(temp_path, "w") as file:
            json.dump(data, file, indent=4)

        temp_path.replace(output_path)

        return output_path


    # ------- VALIDATE LAST SCAN MANIFEST -------


    def validate_scan(scan_result, previous_scan, verbose, log):

        current_scan_path = scan_result.scan_path
        previous_scan_path = previous_scan.get("scan_path")

        if previous_scan_path is None:
            print(O + 'WARNING: Previous scan does not contain scan scope information.\nSkipping comparison.')
            return []

        if current_scan_path != previous_scan_path:
            print(O + 'WARNING: Current scan scope does not match previous scan scope.' + W)
            return []

        previous_files = {
            file["path"]: file
            for file in previous_scan["files"]
        }

        changes = []

        for result in scan_result.files:
            path = str(result.path)

            if path not in previous_files:
                changes.append({
                    "path": path,
                    "change_type": "new_file"
                })
                continue

            previous = previous_files[path]

            md5_match = result.md5 == previous["md5"]
            sha256_match = result.sha256 == previous["sha256"]

            content_changes = {}
            metadata_changes = {}

            previous_modified = datetime.fromisoformat(previous["modified"])
            previous_accessed = datetime.fromisoformat(previous["accessed"])
            previous_created = datetime.fromisoformat(previous["created"])

            if result.size != previous["size"]:
                metadata_changes["size"] = {
                    "previous": previous["size"], 
                    "current": result.size
                    }

            if result.modified != previous_modified:
                metadata_changes["modified"] = {
                    "previous": previous["modified"], 
                    "current": result.modified.isoformat()
                    }

            if result.accessed != previous_accessed:
                metadata_changes["accessed"] = {
                    "previous": previous["accessed"], 
                    "current": result.accessed.isoformat()
                    }

            if result.created != previous_created:
                metadata_changes["created"] = {
                    "previous": previous["created"], 
                    "current": result.created.isoformat()
                    }

            if result.extension != previous["extension"]:
                metadata_changes["extension"] = {
                    "previous": previous["extension"], 
                    "current": result.extension
                    }

            if result.file_type != previous["file_type"]:
                metadata_changes["file_type"] = {
                    "previous": previous["file_type"], 
                    "current": result.file_type
                    }

            if not md5_match:
                content_changes["md5"] = {
                    "previous": previous["md5"], 
                    "current": result.md5
                    }

            if not sha256_match:
                content_changes["sha256"] = {
                    "previous": previous["sha256"], 
                    "current": result.sha256
                    }

            content_changed = bool(content_changes)
            metadata_changed = bool(metadata_changes)

            if not content_changed and not metadata_changed:
                continue

            if content_changed:
                change_type = "content_changed"
            else:
                change_type = "metadata_changed"

            changes.append({
                "path": path,
                "change_type": change_type,

                "hash_validation": {
                    "md5": md5_match,
                    "sha256": sha256_match
                },

                "changes": {
                    "content": content_changes,
                    "metadata": metadata_changes
                }
            })

            if verbose:
                print()
                print(R + f"CHANGED: {result.path}" + W)
            if verbose:
                if content_changed:
                    print('MD5 Hash Validation: ' + R + f'{md5_match}' + W)
                    print('SHA256 Hash Validation: ' + R + f'{sha256_match}' + W)

            if verbose:
                if metadata_changed:
                    print(O + 'Metadata changed.' + W)

        current_files = {
            str(result.path)
            for result in scan_result.files
        }

        for path in previous_files:
            if path not in current_files:
                changes.append({
                    "path": path,
                    "change_type": "removed_file"
                })

        return changes


    # ------- SAVE FILE CHANGES AFTER VALIDATION -------


    def save_changes(changes, log_path):
        log_path = Path(log_path)
        output_path = log_path.with_name(f"{log_path.stem}_report{log_path.suffix}")

        with open(output_path, "w") as file:
            json.dump(changes, file, indent=4)

        print()
        print(G + f"Report saved to: {output_path}" + W)


    # ------- LOAD SCAN -------


    def load_scan(scan_path):
        try:
            with open(scan_path, "r") as file:
                return json.load(file)

        except json.JSONDecodeError as error:
            print(R + f'WARNING: Invalid scan manifest: {scan_path}\n(line {error.lineno}, column {error.colno})' + W)
            return None

        except OSError as error:
            print(R + f'WARNING: Could not load scan manifest {scan_path}: {error}' + W)
            return None


    # -------  LOAD LAST SCAN -------


    def load_previous_scan(compare_path):

        if not compare_path:
            return None

        return load_scan(compare_path)


    # ------- VALIDTAE MD5 & SHA256 -------


    def validate_hashes(calculated_hashes, expected_md5, expected_sha256):
        md5_match = calculated_hashes["md5"].lower() == expected_md5.lower()
        sha256_match = calculated_hashes["sha256"].lower() == expected_sha256.lower()
        invalid_md5 = calculated_hashes["md5"] if not md5_match else None
        invalid_sha256 = calculated_hashes["sha256"] if not sha256_match else None

        return HashValidation(
            md5_match=md5_match,
            sha256_match=sha256_match,
            expected_md5=expected_md5,
            expected_sha256=expected_sha256,
            invalid_md5=invalid_md5,
            invalid_sha256=invalid_sha256
        )


    # ------- CALCULATE FILE HASHES -------


    def calculate_hash(file_path):
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()

        with open(file_path, "rb") as file:
            while chunk := file.read(4096):
                md5.update(chunk)
                sha256.update(chunk)

        return {
            "md5": md5.hexdigest(),
            "sha256": sha256.hexdigest()
        }


    # ------- LOAD EFFECT --------


    def load_effect(stop_event, scan_path):

        spinner = itertools.cycle(['|', '/', '-', '\\'])

        while not stop_event.is_set():

            sys.stdout.write(f"\rScanning {scan_path}... {next(spinner)}")
            sys.stdout.flush()

            time.sleep(0.1)

        sys.stdout.write('\rFinished.                                                                                \n')


    # ------- DISPLAY FILE METADATA -------


    def display_result(result):
        print()
        print('Name: ' + G + f'{result.name}' + W)
        print('Path: ' + G + f'{result.path}' + W)
        print('Size: ' + G + f'{result.size}' + W)
        print('Extension: ' + G + f'{result.extension}' + W)
        print('File Type: ' + G + f'{result.file_type}' + W)
        if result.extension_mismatch:
            print(R + 'WARNING: Extension does not match detected file type.' + W)
        if result.signature:
            print('Signature: ' + C + f'{result.signature.hex(" ")}' + W)
        else:
            print('Signature: ' + GR + 'None detected' + W)
        print('Confidence: ' + C + f'{result.confidence}' + W)
        print('Owner: ' + P + f'{result.owner}' + W)
        print('Group: ' + P + f'{result.group}' + W)
        print('Permissions: ' + P + f'{result.permissions}' + W)
        print('Flags: ' + P + f'{result.flags}' + W)
        print('Inode: ' + P + f'{result.inode}' + W)
        print('Device: ' + P + f'{result.device}' + W)
        print('Link Count: ' + P + f'{result.link_count}' + W)

        print('Modified: ' + O + f'{result.modified}' + W)
        print('Accessed: ' + O + f'{result.accessed}' + W)
        print('Created: ' + O + f'{result.created}' + W)

        print('MD5: ' + B + f'{result.md5}' + W)
        print('SHA256: ' + B + f'{result.sha256}' + W)


    # ------- DISPLAY SCAN SUMMARY -------


    def display_scan_result(scan_result):
        print()
        print('===== Scan Summary =====')
        print()
        print('Scanned: ' + GR + f'{scan_result.scan_path}' + W)
        print('Files Discovered: ' + GR + f'{scan_result.files_discovered}' + W)
        print('Files Analyzed: ' + G + f'{scan_result.files_analyzed}' + W)
        print('Files Failed: ' + R + f'{scan_result.files_failed}' + W)
        print('Total Size: ' + O + f'{scan_result.total_size} bytes' + W)
        print('Hard Link Groups: ' + P + f'{scan_result.hard_link_groups}' + W)


    # ------- ARGUMENTS -------


    def parse_arguments():
        parser = argparse.ArgumentParser(
            description="PyScope forensic filesystem scanner."
        )

        parser.add_argument(
            "path",
            help="path to file or directory to analyze"
        )

        parser.add_argument(
            "--version",
            action="version",
            version="Pyscope 0.3 / Python 3.14.7"
        )

        parser.add_argument(
            "-v", "--verbose",
            action="store_true",
            help="enable verbose output mode"
        )

        parser.add_argument(
            "-l", "--log",
            metavar="PATH",
            help="save scan and change logs to specific path"
        )

        parser.add_argument(
            "-c", "--compare",
            metavar="PATH",
            help="compare current scan against specific scan log"
        )

        parser.add_argument(
            "-r", "--recursive",
            action="store_true",
            help="prform a recursive scan",
        )

        # not yet implemented
        parser.add_argument(
            "-C", "--carve",
            action="store_true",
            help="perform deep data carve"
        )

        return parser.parse_args()


    # ------- MAIN SPACE -------


    def main():

        print()
        print('▄▖  ▄▖            ▄▖  ▄▖  ')
        print('▙▌▌▌▚ ▛▘▛▌▛▌█▌  ▌▌▛▌  ▄▌  ')
        print('▌ ▙▌▄▌▙▖▙▌▙▌▙▖  ▚▘█▌▗ ▄▌  ')
        print('  ▄▌      ▌               ')
        print("Developed by Ethan J. Wells")
        print("https://github.com/wellsej/PyScope")
        print()

        args = parse_arguments()

        if any(character in args.path for character in "*?["):
            analyze_pattern(
                pattern=args.path,
                recursive=args.recursive,
                verbose=args.verbose,
                log=args.log,
                compare=args.compare
            )

        else:
            analyze_path(
                path=Path(args.path),
                recursive=args.recursive,
                verbose=args.verbose,
                log=args.log,
                compare=args.compare
            )
    if __name__ == "__main__":
        main()

except KeyboardInterrupt:
    print()
    print(G + "Thanks for using PyScope!" + W)
