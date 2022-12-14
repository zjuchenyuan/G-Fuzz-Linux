## Changes by G-Fuzz-Linux

Adapted from [https://github.com/sslab-gatech/deadline](https://github.com/sslab-gatech/deadline)

- Python3 support
- LLVM10 support
- Command line flags support and ignore parsing failure
- O0 build

---------

# Deadline

Deadline provide a formal and precise definition of double-fetch bugs and then implement a static analysis system to automatically detect double-fetch bugs in OS kernels. Deadline uses static program analysis techniques to systematically find multi-reads throughout the kernel and employs specialized symbolic checking to vet each multi-read for double-fetch bugs. We apply Deadline to Linux and FreeBSD kernels and find 23 new bugs in Linux and one new bug in FreeBSD.

This repository is provided under the terms of the MIT license.

## Clang build

G-Fuzz skip building LLVM, and use clang provided by apt instead.

```
mkdir -p /g.linux/deadline/llvm/bins
ln -s /usr/bin /g.linux/deadline/llvm/bins/bin
```

## Kernel
(In the case of Linux kernel)

- Setup submodule         : git submodule update --init -- app/linux-stable
- Checkout a version      : ./main.py checkout
- Config                  : ./main.py config
- Build w/gcc (3 hours)   : ./main.py build
- Parse build procedure   : ./main.py parse
- Build w/llvm            : ./main.py irgen

G-Fuzz stops here as we only need bc files.

## Reference
https://ieeexplore.ieee.org/abstract/document/8418630
```
  @inproceedings{xu2018precise,
  title={Precise and scalable detection of double-fetch bugs in OS kernels},
  author={Xu, Meng and Qian, Chenxiong and Lu, Kangjie and Backes, Michael and Kim, Taesoo},
  booktitle={2018 IEEE Symposium on Security and Privacy (SP)},
  pages={661--678},
  year={2018},
  organization={IEEE}
}
```
