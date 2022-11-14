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
git clone https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git /linux-stable
docker run --cpus 25 --name gfuzzlinux -v /linux-stable:/linux-stable -it zjuchenyuan/gfuzz-linux /bin/bash
```

In container:

```
git clone https://github.com/zjuchenyuan/G-Fuzz-Linux /g.linux
mkdir -p mkdir -p /g.linux/deadline/apps
ln -s /linux-stable /g.linux/deadline/apps/linux-stable
mkdir -p /g.linux/deadline/llvm/bins
ln -s /usr/bin /g.linux/deadline/llvm/bins/bin
cd /g.linux/analyzer
cmake -S src -B build
cd /g.linux/deadline
python3 build.py 4.19.204 "https://syzkaller.appspot.com/text?tag=KernelConfig&x=9b9277b418617afe"
```

These steps will build our static analyzer for CG generation, and checkout linux kernel code, run gcc to build the kernel, and then build bc files, and finally run analyzer.

### 2. CG generation

After running command above, we will get `parsed_cg.txt.gz` and `parsed_cg_noindirect.txt.gz` under the folder `/g.linux/analyzer/build/lib/4.19.204`

The CG format is defined as `is_indirect_call caller_fileid@caller_func callee_fileid@callee_func`, and here is a sample:

```
no      13@cma_netdev_change    14@kasan_check_write
no      15@ceph_fill_file_size  16@__dynamic_pr_debug
yes     17@xfs_refcount_merge_right_extent      18@trace_event_raw_event_xfs_refcount_double_extent_class
```

### 3. Distance calculation

### 4. Syscalls inference

### 5. Fuzzing conf generation

### 6. Run fuzzing

### 7. Result analysis