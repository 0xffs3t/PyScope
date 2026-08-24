# PyScope v0.2
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
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Optional
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


# ------- ESTABLISH HASH VALIDATION CLASSES -------


@dataclass
class HashValidation:
    md5_match: bool
    sha256_match: bool
    expected_md5: str
    expected_sha256: str
    invalid_md5: Optional[str]
    invalid_sha256: Optional[str]


# ------- ESTABLISH FILE SIGNATURE CLASSES -------


@dataclass
class FileSignature:
    signature: bytes
    file_type: str
    extensions: list[str]
    offset: int = 0
    confidence: str = "high"


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
    files_discovered: int
    files_analyzed: int
    files_failed: int
    total_size: int
    hard_link_groups: int
    files: list[FileResult]


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
        signature=b"\x52\x49\x46\x46",
        file_type="WAV Audio",
        extensions=[".wav"],
        confidence="high"
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


def analyze_path(path):
    previous_scan = load_previous_scan()

    if path.is_file():
        result = examine_file(path)

        if result:
            display_result(result)

    elif path.is_dir():
        previous_scan = load_previous_scan()

        scan_result = scan_directory(path)

        changes = []

        if previous_scan:
            changes = validate_scan(scan_result, previous_scan)

        save_scan(scan_result)

        if changes:
            save_changes(changes)

        display_scan_result(scan_result)


# ------- CLEAR SCREEN -------


def clear_screen():
    if operating_system == "Windows":
        os.system("cls")
    else:  # macOS and Linux
        os.system("clear")


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


# ------- GET TIMESTAMPS -------


def get_timestamps(file_info):

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


def get_flags(file_info):
    flags = []

    if file_info.st_flags & stat.UF_HIDDEN:
        flags.append("hidden")

    if file_info.st_flags & stat.UF_IMMUTABLE:
        flags.append("immutable")

    if file_info.st_flags & stat.UF_APPEND:
        flags.append("append-only")

    if file_info.st_flags & stat.UF_NOUNLINK:
        flags.append("undeletable")

    if not flags:
        return "None"

    return flags


# ------- GET FILE PERMISSIONS -------


def get_permissions(file_info):
    return stat.filemode(file_info.st_mode)


# -------  GET UID & GID -------


def get_ownership(file_info):
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


# ------- SCAN DIRECTORY AND SUBDIRECTORIES -------


def scan_directory(dir_path):
    directory = Path(dir_path)

    files_discovered = 0
    files_analyzed = 0
    files_failed = 0
    total_size = 0

    file_identities = {}

    file_results = []

# rglob(*) is what makes the scan recursive
    for path in directory.rglob("*"):
        try:
            if path.is_file():
                files_discovered += 1
                result = examine_file(path)

                if result:
                    files_analyzed += 1
                    total_size += result.size
                    file_results.append(result)

                    display_result(result)

                file_id = (result.device, result.inode)

                if file_id in file_identities:
                    file_identities[file_id].append(result.path)
                else:
                    file_identities[file_id] = [result.path]

        except OSError as error:
            files_failed += 1
            print(R + f'Could not analyze {path}: {error}' + W)

    hard_link_groups = 0

    for file_id, paths in file_identities.items():
        if len(paths) > 1:
            hard_link_groups += 1

            print()
            print(O + 'Hard Link Group Detected:' + W)

            for path in paths:
                print(' ' + str(path))

    return ScanResult(
        files_discovered=files_discovered,
        files_analyzed=files_analyzed,
        files_failed=files_failed,
        total_size=total_size,
        hard_link_groups=hard_link_groups,
        files=file_results
    )


# ------- SAVE SCAN TO MANIFEST -------


def save_scan(scan_result):
    script_directory = Path(__file__).resolve().parent
    filename = get_scan_filename()
    output_path = script_directory / filename

    data = {
        "pyscope_version": "0.1",
        "scan_time": datetime.now().isoformat(),
        "files": []
    }

    for result in scan_result.files:
        data["files"].append({
            "name": result.name,
            "path": str(result.path),
            "size": result.size,
            "extension": result.extension,
            "file_type": result.file_type,
            "signature": result.signature,
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
            "sha256": result.sha256
        })

    with open(output_path, "w") as file:
        json.dump(data, file, indent=4)

    return output_path


# ------- GENERATE SCAN MANIFEST NAME -------


def get_scan_filename():
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    return f"scan_{timestamp}.json"


# ------- FIND ALL SCAN MANIFESTS -------


def find_scan_files():
    script_directory = Path(__file__).resolve().parent

    return sorted(script_directory.glob("scan_*.json"))


# ------- LOAD SCAN -------

def load_scan(manifest_path):
    with open(manifest_path, "r") as file:
        return json.load(file)


# -------  LOAD LAST SCAN -------


def load_previous_scan():
    scan_files = find_scan_files()

    if not scan_files:
        return None

    latest_scan = scan_files[-1]

    return load_scan(latest_scan)


# ------- VALIDATE LAST SCAN MANIFEST -------


def validate_scan(scan_result, previous_scan):
    previous_files = {
        file["path"]: file
        for file in previous_scan["files"]
    }

    changes = []

    for result in scan_result.files:
        path = str(result.path)

        if path not in previous_files:
            print()
            print(G + f"NEW FILE: {result.path}" + W)

            changes.append({
                "path": path,
                "change_type": "new_file"
            })

            continue

        previous = previous_files[path]

        md5_match = result.md5 == previous["md5"]
        sha256_match = result.sha256 == previous["sha256"]

        if md5_match and sha256_match:
            continue

        print()
        print(R + f"CHANGED: {result.path}" + W)
        print("MD5 Hash Validation: " + R + f"{md5_match}" + W)
        print("SHA256 Hash Validation: " + R + f"{sha256_match}" + W)

        file_changes = {
            "path": path,
            "change_type": "modified",
            "hash_validation": {
                "md5": md5_match,
                "sha256": sha256_match
            },
            "changes": {}
        }

        if result.size != previous["size"]:
            file_changes["changes"]["size"] = {
                "previous": previous["size"],
                "current": result.size
            }

        if result.extension != previous["extension"]:
            file_changes["changes"]["extension"] = {
                "previous": previous["extension"],
                "current": result.extension
            }

        if result.file_type != previous["file_type"]:
            file_changes["changes"]["file_type"] = {
                "previous": previous["file_type"],
                "current": result.file_type
            }

        if not md5_match:
            file_changes["changes"]["md5"] = {
                "previous": previous["md5"],
                "current": result.md5
            }

        if not sha256_match:
            file_changes["changes"]["sha256"] = {
                "previous": previous["sha256"],
                "current": result.sha256
            }

        changes.append(file_changes)

    return changes


# ------- SAVE FILE CHANGES AFTER VALIDATION -------


def save_changes(changes):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"report_{timestamp}.json"

    script_directory = Path(__file__).resolve().parent
    output_path = script_directory / filename

    with open(output_path, "w") as file:
        json.dump(changes, file, indent=4)

    print(G + f"Report saved to: {output_path}" + W)


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
        end = len(file_signature.signature)

        if header[start:end] == file_signature.signature:
            return file_signature

    return None


# ------- VALIDTAE MD5 & SHA256 -------


def validate_hashes(calculated_hashes, expected_md5, expected_sha256):
    md5_match = calculated_hashes["md5"].lower() == expected_md5.lower()
    sha256_match = calculated_hashes["sha256"].lower(
    ) == expected_sha256.lower()

    return HashValidation(
        md5_match=md5_match,
        sha256_match=sha256_match
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


# ------- DISPLAY FILE METADATA -------


def display_result(result):
    print()
    print('Name: ' + G + f'{result.name}' + W)
    print('Path: ' + G + f'{result.path}' + W)
    print('Size: ' + G + f'{result.size}' + W)
    print('Extension: ' + G + f'{result.extension}' + W)
    print('File Type: ' + G + f'{result.file_type}' + W)
    if result.signature:
        print('Signature: ' + C + f'{result.signature.hex(" ")}' + W)
    else:
        print('Signature: ' + GR + 'None detected' + W)
    print('Confidence: ' + C + f'{result.confidence}' + W)
    print('Owner: ' + P + f'{result.owner}' + W)
    print('Group: ' + P + f'{result.group}' + W)
    print('Permissions: ' + P + f'{result.permissions}' + W)
    if result.extension_mismatch:
        print(R + 'WARNING: Extension does not match detected file type.' + W)
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
    print('===== Scan Complete =====')
    print()
    print('Scanned: ' + GR + f'{input_path}' + W)
    print('Files Discovered: ' + GR + f'{scan_result.files_discovered}' + W)
    print('Files Analyzed: ' + G + f'{scan_result.files_analyzed}' + W)
    print('Files Failed: ' + R + f'{scan_result.files_failed}' + W)
    print('Total Size: ' + O + f'{scan_result.total_size} bytes' + W)
    print('Hard Link Groups: ' + P + f'{scan_result.hard_link_groups}' + W)


# ------- MAIN SPACE -------
# this is where the script starts on the user's end.


operating_system = detect_os()
clear_screen()
print('===========================')
print('▄▖  ▄▖            ▄▖  ▄▖  ')
print('▙▌▌▌▚ ▛▘▛▌▛▌█▌  ▌▌▛▌  ▄▌  ')
print('▌ ▙▌▄▌▙▖▙▌▙▌▙▖  ▚▘█▌▗ ▙▖  ')
print('  ▄▌      ▌               ')
print('===========================')
print()
input_path = input('Path to directory or file > ')
path = Path(input_path)
analyze_path(path)
