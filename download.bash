#!/bin/bash

set -e -o pipefail

function usage() {
    echo 'USAGE:' >&2
    echo '  bash download.bash [[VERSION] DIR]' >&2
    echo >&2
    echo 'This script downloads sisakulint binary from the following release page. curl' >&2
    echo 'command is required as dependency' >&2
    echo 'https://github.com/ultra-supara/sisakulint/releases' >&2
    echo >&2
    echo 'DIR:' >&2
    echo '  Directory to put the downloaded binary (e.g. /path/to/dir). When this value is' >&2
    echo '  omitted, the binary will be put in the current directory.' >&2
    echo >&2
    echo 'VERSION:' >&2
    echo '   Version of sisakulint to download. Version must be a specific version' >&2
    echo '   "{major}.{minor}.{patch}" such as "1.3.5" or "latest". When "latest" is' >&2
    echo '   specified or this argument is omitted, the latest version will be selected.' >&2
    echo >&2
    echo 'EXAMPLE:' >&2
    echo '  - Download the latest binary to the current directory' >&2
    echo >&2
    echo '      $ bash download.bash' >&2
    echo >&2
    echo '  - Download the latest binary to /usr/bin' >&2
    echo >&2
    echo '      $ bash download.bash latest /usr/bin' >&2
    echo >&2
    echo '  - Download version 1.3.5 to the current directory' >&2
    echo >&2
    echo '      $ bash download.bash 1.3.5' >&2
    echo >&2
    echo '  - Download version 1.3.5 to /usr/bin' >&2
    echo >&2
    echo '      $ bash download.bash 1.3.5 /usr/bin' >&2
}

if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    usage
    exit
fi

# Default value is updated manually on release
version="1.0.1"
if [ -n "$1" ]; then
    if [[ "$1" != 'latest' && "$1" != 'LATEST' ]]; then
        if [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            version="$1"
        else
            echo "Given version '$1' does not match to regex '^[0-9]+\.[0-9]+\.[0-9]+$' nor equal to 'latest'" >&2
            echo >&2
            usage
            exit 1
        fi
    fi
fi

target_dir="$(pwd)"
if [ -n "$2" ]; then
    if [ -d "$2" ]; then
        target_dir="${2%/}"
    else
        echo "Directory '$2' does not exist" >&2
        echo >&2
        usage
        exit 1
    fi
fi

echo "Start downloading sisakulint v${version} to ${target_dir}"

case "$OSTYPE" in
    linux-*)
        os=linux
        ext=tar.gz
    ;;
    *)
        echo "OS '${OSTYPE}' is not supported. Note: If you're using Windows, please ensure bash is used to run this script" >&2
        exit 1
    ;;
esac

machine="$(uname -m)"
case "$machine" in
    x86_64) arch=amd64 ;;
    i?86) arch=386 ;;
    aarch64|arm64) arch=arm64 ;;
    arm*) arch=armv6 ;;
    *)
        echo "Could not determine arch from machine hardware name '${machine}'" >&2
        exit 1
    ;;
esac

echo "Detected OS=${os} ext=${ext} arch=${arch}"

# https://github.com/ultra-supara/sisakulint/releases/download/v1.0.0/sisakulint_1.0.0_linux_386.tar.gz
file="sisakulint_${version}_${os}_${arch}.${ext}"
url="https://github.com/ultra-supara/sisakulint/releases/download/v${version}/${file}"

echo "Downloading ${url} with curl"

echo "Downloaded and unarchived executable: ${exe}"

echo "Done: $("${exe}" -version)"

if [ -n "$GITHUB_ACTION" ]; then
    # On GitHub Actions, set executable path to output
    if [ -n "${GITHUB_OUTPUT}" ]; then
        echo "executable=${exe}" >> "$GITHUB_OUTPUT"
    else
        # GitHub Enterprise instance may not introduce the new set-output command yet (see #240)
        echo "::set-output name=executable::${exe}"
    fi
fi
