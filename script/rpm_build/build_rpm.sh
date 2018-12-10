#!/bin/bash

#init
VERSION=$1
if [ "${VERSION}" = "" ]; then
echo "USAGE: ./build_rpm.sh 1.0.0" && exit 0
fi
TAR_NAME="mgw-${VERSION}.tar.gz"
[ ! -f ${TAR_NAME} ] && echo "${TAR_NAME} not existed, exit" && exit 0
rm -rf ~/rpmbuild/BUILD mkdir ~/rpmbuild/BUILD
rm -rf ~/rpmbuild/BUILDROOT mkdir ~/rpmbuild/BUILDROOT
rm -rf ~/rpmbuild/RPMS && mkdir ~/rpmbuild/RPMS
rm -rf ~/rpmbuild/SOURCES && mkdir ~/rpmbuild/SOURCES
rm -rf ~/rpmbuild/SPECS && mkdir ~/rpmbuild/SPECS
rm -rf ~/rpmbuild/SRPMS && mkdir ~/rpmbuild/SRPMS
cp ${TAR_NAME} ~/rpmbuild/SOURCES 

#rpmbuild 
cp ${TAR_NAME} ~/rpmbuild/SOURCES 
cp ./mgw.spec ~/rpmbuild/SPECS
sed -i "s/\$VERSION/${VERSION}/g" ~/rpmbuild/SPECS/mgw.spec
sed -i "s/\$TAR_NAME/${TAR_NAME}/g" ~/rpmbuild/SPECS/mgw.spec
rpmbuild -ba ~/rpmbuild/SPECS/mgw.spec

#cp rpm
cp -rf ~/rpmbuild/RPMS ./
