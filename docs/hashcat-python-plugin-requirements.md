# Hashcat Python Plugin Requirements

## Windows/macOS and Linux

There are significant differences between Windows/macOS and Linux when embedding Python as done here.

### On Windows/macOS

The `multiprocessing` module is not fully supported in this embedded environment, so only a single process can run effectively. In contrast, even though `threading` module does work correctly on Windows/macOS for starting threads and enabling parallelism, most cryptographic functions like `sha256()` block the Global Interpreter Lock (GIL). Since we often run CPU-intensive algorithms (e.g., 10,000 iterations of `sha256()`), this monopolizes the GIL, making the program effectively single-threaded. To achieve true multithreading on Windows/macOS, we need to move to a free-threaded Python runtime.

**On Windows**: Use the official installer from https://www.python.org/downloads/windows/ and ensure you check the "Install free-threaded" option - it's disabled by default. Do not use python from Microsoft Store it's too old.

**On macOS**: Use `pyenv`. It's the easiest way to install and manage Python versions, see below section

### On Linux

The `multiprocessing` module functions correctly, allowing full CPU utilization through parallel worker processes. However, since threading is managed by Python, it relies on `fork()` and inter-process communication (IPC). This adds complexity and code bloat to Hashcat, effectively duplicating modules and bridge plugins, making the codebase harder to understand for those exploring how it all works. We could switch to a free-threaded Python runtime, but it's still unstable at the time of writing even on Linux (see the `cffi` problem below). For now, we’ve chosen to use the `multiprocessing` module as a more practical solution.

**On Linux**: Use `pyenv`. It's the easiest way to install and manage Python versions, see below section

### Free-threaded Python (3.13+)

In order to have multithreading on Windows/macOS, we were looking into Python 3.13 which introduces optional GIL-free support. This allows multithreading to work even in embedded Python. However, it has a major downside. Most relevant modules such as `cffi` still lacks support for running with the Python free-threaded ABI. But if your hash-mode does not rely on modules with `cffi` you should be fine using `-m 72000` no matter the OS.

At the time of writing, several Linux distributions, including Ubuntu 24.04, do not ship with Python 3.13 because it was released after the distro’s feature freeze. You will likely need to install it manually, which is one of the reason we are refering to use `pyenv`.

### Real-world best practice

For now, multiprocessing (-m 73000) supports most modules and is generally better for real-world workloads, but it works only on Linux. Developers on Windows/macOS may use `-m 72000` for development, except if `cffi` modules are requested and in this case switch back to `-m 73000`. Then use Linux (or WSL2 on Windows) for long running tasks.

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

Note that unlike on Windows, there is no combined Python 3.13 + 3.13t version. This can be a bit confusing. If you plan to use `-m 72000`, you must switch your pyenv to Python `3.13t` beforehand. Similarly, you need to switch back to Python `3.13` before using `-m 73000`.
