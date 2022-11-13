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

### 2. CG generation

### 3. Distance calculation

### 4. Syscalls inference

### 5. Fuzzing conf generation

### 6. Run fuzzing

### 7. Result analysis