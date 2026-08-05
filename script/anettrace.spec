Summary: A skb (network package) trace tool for kernel

Name: anettrace

Version: %{VERSION}

Release: %{?dist}

License: MulanPSL-2.0

BuildRoot:%{_tmppath}/%{name}-%{version}-%{release}-root

Group: Development/Tools

Source0:%{name}-%{version}.tar.gz

# URL:

%define __strip ${CROSS_COMPILE}strip
%define __objdump ${CROSS_COMPILE}objdump

%description
Anettrace is a powerful tool to trace network packets and diagnose
network problems inside Linux and rooted Android kernels.

It uses eBPF.

'skb' is the struct that used in kernel to store network package.
By tracing kernel functions with eBPF fentry, fexit, and tp_btf,
Anettrace can show the path of an skb through the kernel network
stack and help diagnose issues such as packet drops.

%prep
%setup -q

%install
rm -rf $RPM_BUILD_ROOT
make PREFIX=$RPM_BUILD_ROOT install
PREFIX=$RPM_BUILD_ROOT

%files
%defattr (-,root,root,0755)
/usr/bin/anettrace
/usr/share/man/zh_CN/man8/anettrace.8.gz
/usr/share/man/man8/anettrace.8.gz
/usr/share/man/man8/dropreason.8.gz
/usr/share/bash-completion/completions/anettrace
/usr/share/fish/vendor_completions.d/anettrace.fish

%doc

%changelog
