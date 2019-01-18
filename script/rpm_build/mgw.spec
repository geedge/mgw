Name: mgw		
Version: $VERSION
Release:	1%{?dist}
Summary: matrix gateway

License: GPL	
Source0: $TAR_NAME


%description
matrix gateway for IPREUSE

%prep
%setup -q


%build
mkdir build  && cd build
cmake -DCMAKE_BUILD_TYPE=Debug ../
make

%install
mkdir -p %{buildroot}/opt/mgw/script
mkdir -p %{buildroot}/opt/mgw/ip_locator/db/v4/
cp -f ./README.md %{buildroot}/opt/mgw
cp -f ./build/access/mgw %{buildroot}/opt/mgw
cp -rf ./conf/ %{buildroot}/opt/mgw
cp -rf ./script/systemd %{buildroot}/opt/mgw/script
mkdir %{buildroot}/vendor && tar -xzvf ./vendor/IPLocator-master.tar.gz -C %{buildroot}/vendor/
cp -f %{buildroot}/vendor/IPLocator-master/db/v4/all_ip_info_v4.mmdb  %{buildroot}/opt/mgw/ip_locator/db/v4/all_ip_info_v4.mmdb

%define _unpackaged_files_terminate_build 0

%files
/opt/mgw/*

%post
cp -f /opt/mgw/script/systemd/mgw.service /etc/systemd/system/mgw.service
systemctl daemon-reload
systemctl enable mgw.service

%postun
rm /etc/systemd/system/mgw.service
systemctl daemon-reload

%clean
rm -rf $RPM_BUILD_DIR/*
rm -rf %{buildroot}/../*
%changelog

