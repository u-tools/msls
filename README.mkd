<!DOCTYPE markdown>

# `msls`

`msls` is a port of GNU `ls` onto the MS-Windows platform.

## Description

`msls` is an adaptation of the GNU `ls` directory information utility for
Microsoft Windows. It lists exhaustive information on on Windows files
in a format familiar to UNIX users, including information on DACLs/SACLs,
integrity levels, reparse points, shortcuts, hard links, symbolic links,
hidden streams, encryption, compaction, virtualization,
object tracking identifier, and offline status.

See the [documentation](https://u-tools.com/msls.htm) for details.

You can download `ls` at [u-tools.com/msls](https://u-tools.com/msls).
Also included is a native Windows version of the `grep` text search utility.

The primary repository is hosted on github at https://github.com/u-tools/msls

## Requirements

- Microsoft Visual C/C++ (`cl` v12.00+) and tools
  - free versions are available (see [Visual Studio Express](https://visualstudio.microsoft.com/vs/express))

## Build Instructions

    git clone https://github.com/u-tools/msls REPO_DIR
    cd REPO_DIR
    build &:: "release" is the default target

Build artifacts will be produced out-of-source, being placed in the "#build" subdirectory of REPO_DIR.

`build help` will show all available build targets. Some other specific build targets are:

|                 |                                        |
|-----------------|----------------------------------------|
| `build all`     | build both debug and release artifacts |
| `build clean`   | clean up all build artifacts           |
| `build debug`   | build debug artifacts                  |
| `build release` | build release artifacts                |

## Installation

To install: Copy "ls.exe" from the build directory to your favorite executable folder for your
32-bit command line utilities (eg, `copy ls.exe C:\Windows\SysWOW64\ls.exe`

## Documentation

For documentation see https://u-tools.com/msls.htm

### LS_OPTIONS

Set the "LS_OPTIONS" environment variable in Control Panel -> System
-> Advanced -> Environment Variables.  The recommended option settings are:

    -bhAC --more --color=auto --recent --streams

For `grep` the recommended settings for "GREP_OPTIONS" are:

    --binary-files=text -d skip --color=auto

## Acknowledgements

The port was written by Alan Klietz of [U-Tools Software](https://u-tools.com).
Additional patches and a streamlined build process were contributed by [Roy Ivy III](https://github.com/rivy).

