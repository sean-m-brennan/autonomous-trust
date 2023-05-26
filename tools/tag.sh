#!/bin/bash

this_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)

src_dirs="${this_dir}/../src/autonomous-trust ${this_dir}/../src/autonomous-trust-inspector"

current_version=$(git describe | sed 's/v//')
major=$(echo $current_version | awk -F. '{print $1}')
minor=$(echo $current_version | awk -F. '{print $2}')
patch=$(echo $current_version | awk -F. '{print $3}')

# shellcheck disable=SC2199
if [[ "$@" = *"--major"* ]]; then
    major=$((major+1))
    minor=0
    patch=0
elif [[ "$@" = *"--minor"* ]]; then
    minor=$((minor+1))
    patch=0
elif [[ "$@" = *"--patch"* ]]; then
    patch=$((patch+1))
else
    echo "Specify increment: '--major', '--minor', or '--patch'"
    exit 1
fi

next_version=${major}.${minor}.${patch}

echo -n "Tagging v$next_version.   "
read -p "Commit? (y/N) " do_commit
do_commit=$(echo "$do_commit" | awk '{print tolower($0)}')
if [[ "$do_commit" != "y"* ]]; then
    echo "  Cancelled"
    exit 0
fi

for dir in $src_dirs; do
    sed -i "s/version.*=.*\".*\"/version = \"$next_version\"/" $dir/pyproject.toml
done
git commit -a -m"Release v$next_version"
git tag -a v$next_version -m"Release v$next_version"
