# PyScope v0.1
# Ethan J. Wells
# 8/23/2026
# PyScope is an open-source recursive forensic file scanner developed as a learner project.
# Originally developed on MacOS, but with compatibility in mind.

import os
import sys
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Optional
from dataclasses import dataclass

W = '\033[0m'  # white (normal)
R = '\033[31m'  # red
G = '\033[32m'  # green
O = '\033[33m'  # orange
B = '\033[34m'  # blue
P = '\033[35m'  # purple
C = '\033[36m'  # cyan
GR = '\033[37m'  # gray


@dataclass
class FileSignature:
    signature: bytes
    file_type: str
    extensions: list[str]
    offset: int = 0
    confidence: str = "high"


@dataclass
class FileResult:
    name: str
    path: Path
    size: int
    extension: str
    file_type: str
    signature: Optional[bytes]
    confidence: str
    extension_mismatch: bool
    modified: datetime
    accessed: datetime
    created: datetime
    md5: str
    sha256: str


@dataclass
class ScanResult:
    files_discovered: int
    files_analyzed: int
    files_failed: int
    total_size: int


def analyze_path(path):
    path = Path(path)

    if path.is_file():
        result = examine_file(path)

    if result:
        display_result(result)

    elif path.is_dir():
        scan_directory(path)

    else:
        print(R + 'The path does not exist or is not a file or directory.')


def scan_directory(dir_path):
    directory = Path(dir_path)

    files_discovered = 0
    files_analyzed = 0
    files_failed = 0
    total_size = 0

    for path in directory.rglob("*"):
        if path.is_file():
            files_discovered += 1
            try:
                result = examine_file(path)

                if result:
                    files_analyzed += 1
                    total_size += result.size
                    display_result(result)
            except OSError as error:
                files_failed += 1
                print(R + f'Could not analyze {path}: {error}' + W)

    return ScanResult(
        files_discovered=files_discovered,
        files_analyzed=files_analyzed,
        files_failed=files_failed,
        total_size=total_size
    )


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


def check_extension(file_extension, file_signature):
    if file_signature is None:
        return False

    return file_extension.lower() not in file_signature.extensions


def detect_file_type(file_path):
    with open(file_path, "rb") as file:
        header = file.read(32)

    for file_signature in FILE_SIGNATURES:
        start = file_signature.offset
        end = len(file_signature.signature)

        if header[start:end] == file_signature.signature:
            return file_signature

    return None


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


def examine_file(input_path):
    file = Path(input_path)

    if not file.exists():
        print(R + 'File does not exist.')
        return

    if not file.is_file():
        print(R + 'The path is not a file.')
        return

    file_info = file.stat()

    modified_time = datetime.fromtimestamp(file_info.st_mtime)
    accessed_time = datetime.fromtimestamp(file_info.st_atime)
    created_time = datetime.fromtimestamp(file_info.st_ctime)

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
        extension_mismatch=extension_mismatch,
        modified=modified_time,
        accessed=accessed_time,
        created=created_time,
        md5=md5_hash,
        sha256=sha256_hash
    )


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
    if result.extension_mismatch:
        print(R + 'WARNING: Extension does not match detected file type.' + W)

    print('Modified: ' + O + f'{result.modified}' + W)
    print('Accessed: ' + O + f'{result.accessed}' + W)
    print('Created: ' + O + f'{result.created}' + W)

    print('MD5: ' + B + f'{result.md5}' + W)
    print('SHA256: ' + B + f'{result.sha256}' + W)


def display_scan_result(scan_result):
    print()
    print('===== Scan Complete =====')
    print()
    print('Scanned: ' + GR + f'{input_path}' + W)
    print('Files Discovered: ' + GR + f'{scan_result.files_discovered}' + W)
    print('Files Analyzed: ' + G + f'{scan_result.files_analyzed}' + W)
    print('Files Failed: ' + R + f'{scan_result.files_failed}' + W)
    print('Total Size: ' + O + f'{scan_result.total_size} bytes' + W)


def clear_screen():
    if os.name == "nt":  # Windows

        # use os.system for legacy Windows, fallback to ANSI for modern Windows
        if os.system("cls") != 0:
            sys.stdout.write("\033[H\033[2J")
            sys.stdout.flush()

    else:  # macOS and Linux
        sys.stdout.write("\033[H\033[2J")
        sys.stdout.flush()


# this is where the script starts on the user's end.
clear_screen()
print()
print('===== PyScope v0.1 =====')
print()
input_path = input('Path to directory or file > ')
path = Path(input_path)

# determine if input is a valid file or directory then examine/scan accordingly
if path.is_file():
    result = examine_file(path)

    if result:
        display_result(result)

elif path.is_dir():
    scan_result = scan_directory(path)
    display_scan_result(scan_result)

else:
    print(R + 'The path does not exist or is not a file or directory.')
