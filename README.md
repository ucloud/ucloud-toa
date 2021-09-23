# TCP Option Address

The TCP Option Address (TOA) module is a kernel module that obtains the client IPv4 address from the option section of a TCP header.

It's typically used on the backends of LVS(toa enable).

### Features

1. Support kernel from 2.6.32 to the mainline now
2. Support IPV6 listen(golang default method)

### Requirements

1. Install kernel-devel, kernel-headers related kernel development packages which match the running kernel.
2. Install gcc and make

### Usage

1. Compiling the module

```bash
make
```

2. Load the module

```bash
insmod ./toa.ko
```

## Distribution license

TOA is distributed under the terms of the GNU General Public License v2.0. The full terms and conditions of this license are detailed in the LICENSE file.
