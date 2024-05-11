%define _unpackaged_files_terminate_build 1

Name: libcng-dpapi
Version: 0.0.1
Release: alt1

Summary: Client library for CNG-DPAPI
License: GPLv2+
Group: Development
Url: https://github.com/august-alt/libcng-dpapi

BuildRequires: rpm-macros-cmake cmake cmake-modules gcc-c++
BuildRequires: doxygen

Requires: cmake

Source0: %name-%version.tar

%description
Client library for CNG-DPAPI

%prep
%setup -q

%build
%cmake
%cmake_build

%install
%cmakeinstall_std

%files
%doc README.md
%doc INSTALL.md

%_includedir/cng-dpapi/*.h
%_libdir/libcng-dpapi.so
%_libdir/cng-dpapi/CNGDpApiConfig.cmake

%changelog
* Sun May 12 2024 Vladimir Rubanov <august@altlinux.org> 0.0.1-alt1
- 0.0.1-alt1
- Initial build
