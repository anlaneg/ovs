#! /bin/bash
DEB_BUILD_OPTIONS='parallel=8 nocheck’ dpkg-buildpackage -b -us -uc -d
