#! /bin/bash
VERSION="`git log --pretty=format:\"%h\" -1`"
DEBEMAIL="owner <owner@example.com>"
export DEBEMAIL
dch -D unstable -i "New unstable version:$VERSION"
DEB_BUILD_OPTIONS='parallel=8 nocheck’ dpkg-buildpackage -b -us -uc -d
