---
name: Bug report
about: Something is not working as expected
title: ''
labels: bug
assignees: ''

---

**GitHub is for bugs and features - not for support**
For support, please use the hashcat forums https://hashcat.net/forum/

**Check the FAQ**
Some items that might appear to be issues are not issues. Please review the hashcat FAQ https://hashcat.net/wiki/doku.php?id=frequently_asked_questions before submitting a bug report.

**Describe the bug**
A clear and concise description of what the bug is.

**To Reproduce**
Please provide us with all files required to reproduce the bug locally on our development systems. For instance: hash files, wordlists, rule files, ...

**Expected behavior**
A clear and concise description of what you expected to happen.

**Hardware/Compute device (please complete the following information):**
- Compute device name: [e.g. RTX2080Ti]
- OpenCL/CUDA driver name: [e.g. NVIDIA DRIVER]
- OpenCL/CUDA driver version: [e.g. 465.21]
- OpenCL/CUDA driver source: [e.g. runtime installer/.exe installer]

**Hashcat version (please complete the following information):**
 - OS: [e.g. Linux]
 - Distribution: [e.g. Ubuntu 18.04]
 - Version: [e.g. 6.2.0]

**Diagnostic output compute devices:**


```
For NV: Post nvidia-smi output. This tool also exist on Windows
For AMD ROCm: Post rocm-smi and rocminfo output
```

```
Post clinfo output
```

```
Post hashcat -I output
```

```
On Linux: post lspci output
```

**Additional context**
Add any other context about the problem here. For instance, it was working with hashcat version X.X.X (also please post output from older versions).
