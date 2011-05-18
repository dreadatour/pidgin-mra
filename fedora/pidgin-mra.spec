Name:		pidgin-mra
Version:	git20101118
Release:	1%{?dist}
Summary:	Mail.ru Agent protocol plugin for Pidgin IM

Group:		Applications/Communications
License:	GPLv3+
URL:		https://github.com/dreadatour/pidgin-mra
Source0:	%{name}-%{version}.tar.bz2
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:	glib2-devel
BuildRequires:	libpurple-devel
Requires:	pidgin
Requires:	libpurple

%description
This is Mail.ru Agent protocol plugin for Pidgin IM

%prep
%setup -q
chmod 0644 src/*.c src/*.h img/*.png
chmod 0644 ChangeLog COPYING INSTALL Makefile README TODO

%build
make %{?_smp_mflags} LIBDIR=%{_libdir}

%install
rm -rf %{buildroot}
make LIBDIR=%{_libdir} DESTDIR=%{buildroot} install

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%doc ChangeLog COPYING README TODO
%{_libdir}/purple-2/*.so
%{_datadir}/pixmaps/pidgin/protocols/*/mra.png


%changelog
* Thu Nov 18 2010 Alexei Panov <elemc@atisserv.ru> - git20101118-1
- Initial build
