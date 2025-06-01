# Hashcat Python Plugin Requirements

## Windows and Linux/macOS

There are significant differences between Windows and Linux/macOS when embedding Python as done here.

### On Windows

The `multiprocessing` module is not fully supported in this embedded environment, so only a single process can run effectively. In contrast, the `threading` module does work correctly on Windows for starting threads and enabling parallelism. However, most cryptographic functions like `sha256()` block the Global Interpreter Lock (GIL). Since we often run CPU-intensive algorithms (e.g., 10,000 iterations of `sha256()`), this monopolizes the GIL, making the program effectively single-threaded. To achieve true multithreading on Windows, we need to move to a free-threaded Python runtime.

**On Windows**: Use the official installer from https://www.python.org/downloads/windows/ and ensure you check the "Install free-threaded" option - it's disabled by default.

Do not use python from Microsoft Store it's too old.

### On Linux/macOS

The `multiprocessing` module functions correctly, allowing full CPU utilization through parallel worker processes. However, since threading is managed by Python, it relies on `fork()` and inter-process communication (IPC). This adds complexity and code bloat to Hashcat, effectively duplicating modules and bridge plugins, making the codebase harder to understand for those exploring how it all works. We could switch to a free-threaded Python runtime, but it's still unstable at the time of writing even on Linux (see the `cffi` problem below). For now, we’ve chosen to use the `multiprocessing` module as a more practical solution.

**On Linux/macOS**: Use `pyenv`. It's the easiest way to install and manage Python versions, see below section

### Free-threaded Python (3.13+)

In order to have multithreading on Windows, we were looking into Python 3.13 which introduces optional GIL-free support. This allows multithreading to work even in embedded Python. However, it has a major downside. Most relevant modules such as `cffi` still lacks support for running with the Python free-threaded ABI. But if your hash-mode does not rely on modules with `cffi` you should be fine using `-m 72000` no matter the OS.

At the time of writing, several Linux distributions, including Ubuntu 24.04, do not ship with Python 3.13 because it was released after the distro’s feature freeze. You will likely need to install it manually, which is one of the reason we are refering to use `pyenv`.

### Real-world best practice

For now, multiprocessing (73000) supports most modules and is generally better for real-world workloads, but it works only on Linux. Developers may use `-m 73000` on Linux for performance and `-m 72000` on Windows for development.

### Pyenv

Pyenv is great for managing local python versions, and also frees us from using virtual environments while at the same time to not break global system installs when using `pip` to install new modules.

Check out https://github.com/pyenv/pyenv in order how to install `pyenv`.

After install, if you are fine with `-m 73000`

```
pyenv install 3.13
pyenv local 3.13
```

In order to use `-m 72000`

```
pyenv install 3.13t
pyenv local 3.13t
```
