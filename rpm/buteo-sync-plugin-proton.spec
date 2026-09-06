Name:           buteo-sync-plugin-proton
Summary:        Buteo sync plugin for Proton Contacts
Version:        0.1.0
Release:        1
License:        GPL-3.0-or-later
URL:            https://github.com/yourusername/sailfish-proton
Source0:        %{name}-%{version}.tar.bz2

Requires:       buteo-syncfw-qt5 >= 0.11
Requires:       qt5-qtpim-contacts
Requires:       mkcal-qt5
Requires:       kf5-calendarcore
Requires:       libaccounts-qt5 >= 1.16
Requires:       libsignon-qt5 >= 8.61
Requires:       glibc >= 2.17

%description
Buteo synchronization plugin for Proton Contacts and Calendar. Single OOPP
plugin (libproton-client.so, Sync Protocol "proton") handles both
proton-carddav (contacts, QContactManager) and proton-caldav (calendar,
mKCal/KCalendarCore) sync profiles.

%prep
%setup -q -n %{name}-%{version}

%build
echo "Verifying pre-built plugin"
ls -lh buteo-plugin/libproton-client.so

%install
rm -rf %{buildroot}

mkdir -p %{buildroot}%{_libdir}/buteo-plugins-qt5/oopp
install -m 0755 buteo-plugin/libproton-client.so \
    %{buildroot}%{_libdir}/buteo-plugins-qt5/oopp/libproton-client.so

mkdir -p %{buildroot}%{_sysconfdir}/buteo/profiles/client
install -m 0644 buteo-profiles/client/proton-contacts.xml \
    %{buildroot}%{_sysconfdir}/buteo/profiles/client/proton.xml

mkdir -p %{buildroot}%{_sysconfdir}/buteo/profiles/sync
install -m 0644 buteo-profiles/sync/proton.Contacts.xml \
    %{buildroot}%{_sysconfdir}/buteo/profiles/sync/proton.Contacts.xml
install -m 0644 buteo-profiles/sync/proton.Calendar.xml \
    %{buildroot}%{_sysconfdir}/buteo/profiles/sync/proton.Calendar.xml

%files
%defattr(-,root,root,-)
%{_libdir}/buteo-plugins-qt5/oopp/libproton-client.so
%config(noreplace) %{_sysconfdir}/buteo/profiles/client/proton.xml
%config(noreplace) %{_sysconfdir}/buteo/profiles/sync/proton.Contacts.xml
%config(noreplace) %{_sysconfdir}/buteo/profiles/sync/proton.Calendar.xml

%post
systemctl --user reload msyncd 2>/dev/null || true

%postun
systemctl --user reload msyncd 2>/dev/null || true

%changelog
* %(date +"%a %b %d %Y") Marco Napetti <marco.napetti@proton.me> - 0.1.0-1
- Initial packaging
