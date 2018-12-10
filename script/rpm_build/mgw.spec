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
rm -rf /opt/mgw && mkdir /opt/mgw
mkdir -p %{buildroot}/opt/mgw/script
cp ./README.md %{buildroot}/opt/mgw
cp -f ./build/access/mgw %{buildroot}/opt/mgw
cp -rf ./conf/ %{buildroot}/opt/mgw
cp -rf ./script/systemd %{buildroot}/opt/mgw/script

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

