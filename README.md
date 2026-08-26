# PyScope
An open-source recursive forensic file scanning tool developed as a learner project. This project is actively being worked on and will improve along with my skills in Python. I plan to add more advanced features, polish the code and add more comments for fellow learners.


<img width="972" height="611" alt="Screenshot 2026-08-26 at 1 45 38 AM" src="https://github.com/user-attachments/assets/e83f5322-779f-449d-86ad-b1e52f1e93a6" />



# Usage examples:
------
```
usage: pyscope.py [-h] [--version] [-v] [-l PATH] [-c PATH] [-r] [-C] path

PyScope forensic filesystem scanner.

positional arguments:
  path                path to file or directory to analyze

options:
  -h, --help          show this help message and exit
  --version           show program's version number and exit
  -v, --verbose       enable verbose output mode
  -l, --log PATH      save scan and change logs to specific path
  -c, --compare PATH  compare current scan against specific scan log
  -r, --recursive     prform a recursive scan

Standard file scan:
>  python pyscope.py [-r -v ] /path/to/file.bin

Standard directory scan:
>  python pyscope.py /path/to/dir

Pattern scanning:
>  python pyscope.py "/home/user/pictures/*.jpg"

```


Features include:
======
  - Individual file examination
  - Recursive directory scanning
  - Pattern scanning
  - Checking file format signatures
  - MD5 & SHA256 hash calculation & validation
  - Simple signature confidence
  - Error handling
  - Cross-platform compatibility
  - Save scans to json file
  - Detect changes in files and save reports to json file
  - Detect hard link groups
  - Display UID & GID in scan summary
  - Display file permissions
  - Display file flags
  - OS detection
  - Some fancy ASCII art

# Changelog

All notable changes to this project will be documented in this file.

## - 2026-08-25
### Added
- Pattern scanning
- Argument powered CLI architecture
- Cycling ASCII text when scanning
- KeyboardInterrupt handling
- Enhanced error handling
- Enhanced workflow

### Fixed
- JSON serialization bug prevent scans writing to file
- Enhanced distinction between RIFF & WAVE file signatures
- Removed obsolete code
- Reduced redundant code
- Refined functions
------

## - 2026-08-24
### Added
- Added a new dark mode toggle to the settings menu.
- Implemented user profile customization options.
- Save scans to json file
- Detect changes in files and save reports to json file
- Detect hard link groups
- Display UID & GID in scan summary
- Display invalid MD5/SHA256 hashes from previous scans.
- Display file permissions
- Display file flags
- OS detection
- Some fancy ASCII art

### Fixed
- Fixed a bug causing the application to crash when handling certain errors.

## - 2026-08-23
### Added
- Initial release of the project.

# Known bugs:
  - [FIXED] ~~Crash when handling: PermissionError: [Errno 13] Permission denied: '/usr/sbin/weakpass_edit'~~
  - [FIXED] ~~JSON unable to serialize signature value due to it being a bytes object.~~
  - Operation will timeout reading some files.
======


Lessons I've learned so far:
=============================================
  1) Comment, comment, comment. Comments make the code easier to read and maintain. I wish had started adding them sooner, it's made finding specific functions easier.
  2) Organize the code. When I first started, it was easy to find functions and specific lines, but as it grew, it became harder. I started organizing functions by moving them closer to similar functions, so it's like sorting functions by category.
  3) Google, StackOverflow, and just forums in general are your friend. There is always a useful piece of information out there that can help fill in the blanks and help breakdown any roadblock.
  4) AI is a helpful tool when trying to learn how somethings work, but relying on it will leave you tangled in a messy web of redundant code.
  5) Take breaks. After looking at a screen for so long managing code, your brain kind of becomes a potato and it becomes harder to spot things.
  6) Take notes. If you see a piece of code that you want or need to improve then either take note of it or tackle it right then and there, because if you just try taking a mental note of it and continue with other things, there is a good chance that you will forget about it and it will sit there until something breaks and you have figure out what's going on.
