# G-Fuzz-Linux
directed fuzzing for linux kernel


## Steps

1. Use deadline to compile Linux kernel to LLVM bc files
2. Use MLTA algorithm to get function call graph, taking indirect calls into consideration
3. Function level distance calculation
4. Syscall inference using rules based on CG and crash report
5. Generate fuzzing conf files
6. Run syzkaller to conduct experiments
7. Result collection

### 1. Compile linux kernel

We provide a easier build environment docker image `zjuchenyuan/gfuzz-linux` [Dockerfile](https://github.com/zjuchenyuan/G-Fuzz-Linux/blob/master/Dockerfile) based on [zjuchenyuan/gollvm](https://github.com/zjuchenyuan/gfuzz/blob/main/dockerfiles/Dockerfile.gollvm), and we assume you clone this repo to /g.linux

We use linux `4.19.204` version, and kernel config provided by [syzbot](https://syzkaller.appspot.com/bug?id=e2309c1c341d4c7f70f50225c11d5fdc99372086)

We recommend git clone kernel into a host directory, and mount it to container, like: ( you may change `--cpus` parameter as you wish )

```
git clone https://github.com/zjuchenyuan/G-Fuzz-Linux /g.linux
git clone https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git /linux-stable
docker run --cpus 25 --name gfuzzlinux -v /g.linux:/g.linux -v /linux-stable:/linux-stable -it zjuchenyuan/gfuzz-linux /bin/bash
```

In container:

```
mkdir -p /g.linux/deadline/apps
ln -s /linux-stable /g.linux/deadline/apps/linux-stable
mkdir -p /g.linux/deadline/llvm/bins
ln -s /usr/bin /g.linux/deadline/llvm/bins/bin
cd /g.linux/analyzer
cmake -S src -B build
cd /g.linux/analyzer/build
make
cd /g.linux/deadline
python3 build.py 4.19.204 "https://syzkaller.appspot.com/text?tag=KernelConfig&x=9b9277b418617afe"
```

These steps will build our static analyzer for CG generation, and checkout linux kernel code, run gcc to build the kernel, and then build bc files, and finally run analyzer.

Then we need a translation between function and basic block pcs. We use addr2line as described [here](https://github.com/google/syzkaller/blob/master/docs/linux/coverage.md).
This step may take several minutes, we are looking other better/optimized way to convert function to its pcs. (If you have one, do not hesitate to submit an issue.)

```
cd /g.linux/deadline/code/objs/linux-stable-4.19.204
objdump -d --no-show-raw-insn  vmlinux|grep __sanitizer_cov_trace_pc|cut -d: -f1 |addr2line -afi -e vmlinux|gzip > allpcs_addr2line.txt.gz
cd /g.linux/analyzer/build/lib/4.19.204
python3  /g.linux/analyzer/parse_addr2line_getfunc2pcs.py
```

### 2. CG generation

After running command above, we will get `parsed_cg.txt.gz` and `parsed_cg_noindirect.txt.gz` under the folder `/g.linux/analyzer/build/lib/4.19.204`

The CG format is defined as `is_indirect_call caller_fileid@caller_func callee_fileid@callee_func`, and here is a sample:

```
no      13@cma_netdev_change    14@kasan_check_write
no      15@ceph_fill_file_size  16@__dynamic_pr_debug
yes     17@xfs_refcount_merge_right_extent      18@trace_event_raw_event_xfs_refcount_double_extent_class
```

As there are same-name function distributed in different files, so we need add filepath into our representation of function. Making it short, we create a relationship between fileid and real filepath using file `fileid.json`.

### 3. Distance calculation

In this example, we choose this crash report [general protection fault in cdev_del](https://syzkaller.appspot.com/bug?id=e2309c1c341d4c7f70f50225c11d5fdc99372086).

The target function can be set as `tty_unregister_device` of `drivers/tty/tty_io.c`

For easier use, we call this target as `id=1`, so we run `python3 /g.linux/scripts/cgdis.py <id> <version> <function name> <file path>` as:

```
cd /g.linux/example
python3 /g.linux/scripts/cgdis.py 1 4.19.204 tty_unregister_device drivers/tty/tty_io.c
```

And we will get `cgdis_1.json`, which translate pc to distance.

### 4. Syscalls inference

The crash report is placed at `example/crashreport1.txt`, let's leverage G-Fuzz inference rules to get related syscalls.

```
cd /g.linux/example
python3 /g.linux/scripts/report_syscall_inference.py crashreport1.txt
```

It will output `["exit_group", "syz_open_dev$tty1", "syz_open_dev$tty20", "syz_open_dev$ttys"]`, copy this output, as we will use it in our conf file.

### 5. Fuzzing preparation and conf generation

To run the fuzzing, we need to compile syzkaller and prepare an OS image.

```
cd /
wget -q https://golang.org/dl/go1.15.3.linux-amd64.tar.gz
tar xf go1.15.3.linux-amd64.tar.gz
export PATH=/go/bin:$PATH
cd /g.linux/syzkaller
make
```

Please follow [official guidance](https://github.com/google/syzkaller/blob/master/docs/linux/setup_ubuntu-host_qemu-vm_x86-64-kernel.md#image) to create an image under `/g.linux/image`.

Then, write a fuzzing conf file required by Syzkaller, you can take a look at [example1.conf](example/example1.conf).

### 6. Run fuzzing

We recommend running syzkaller outside the container.

```
mkdir -p /g.linux/output/example/example1
cd /g.linux/output/example/example1
/g.linux/syzkaller/bin/syz-manager -conf /g.linux/example/example1.conf
```

### 7. Result analysis

G-Fuzz will write a `foundtime` file for each crash found, which records crash found time relative to fuzzing start.
