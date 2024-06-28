#!/bin/sh

curl https://storage.googleapis.com/git-repo-downloads/repo > ~/bin/repo
chmod a+x ~/bin/repo

repo init -u "ssh://git@github.com/Parrot-Developers/airsdk-samples-manifest" -b the-hard-way
repo sync

./build.sh -p pc -t download-base-sdk