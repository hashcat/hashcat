
# Hashcat – Build Documentation

**Revision**: 1.8
**Author**: See `docs/credits.txt`

---

## ✅ Requirements

- **Python 3.12** or higher

Check your Python version:

```bash
$ python3 --version
# Expected output: Python 3.14.3
```

If you can't install Python ≥ 3.12 globally, you can use **pyenv**.

> If you're using `pyenv`, follow **all steps** below. Otherwise, follow only **steps 3 and 5**.

---

## 🛠️ Building Hashcat – Step-by-Step

### 🔹 Step 1: Install dependencies and pyenv

#### On Linux

Install required packages via apt:

```bash
$ sudo apt install libbz2-dev libssl-dev libncurses5-dev libffi-dev libreadline-dev libsqlite3-dev liblzma-dev libomp-dev git
```

Install `pyenv`:

```bash
$ curl https://pyenv.run | bash
```

> Follow the instructions shown after installation to set up your shell correctly.

#### On macOS

Install required packages via Homebrew:

```bash
$ brew install pyenv llvm libomp
```

Add `llvm` to your PATH:

```bash
echo "$(brew --prefix llvm)/bin" >> ~/.bashrc
```

---

### 🔹 Step 2: Install Python using pyenv

Install Python 3.12 (or newer):

```bash
$ pyenv install 3.14.3
```

Check installed versions:

```bash
$ pyenv versions
# Example:
# * system
#   3.14.3
```

---

### 🔹 Step 3: Install Rustup

```bash
$ curl https://sh.rustup.rs -sSf | sh -s -- -y
$ . "$HOME/.cargo/env"
```

---

### 🔹 Step 4: Clone the Hashcat repository

```bash
$ git clone https://github.com/hashcat/hashcat.git
$ cd hashcat
```

---

### 🔹 Step 5: Set the local Python version

```bash
$ pyenv local 3.14.3
```

---

### 🔹 Step 6: Build Hashcat

```bash
$ make clean && make
```

---

### 🔹 Step 7 (Optional): Install Hashcat (Linux only)

```bash
$ make install
```

Hashcat will use the following locations depending on your environment:

| Condition                                   | Session Files                          | Kernel Cache                          | Potfiles                              |
|--------------------------------------------|----------------------------------------|---------------------------------------|----------------------------------------|
| `$XDG_DATA_HOME` and `$XDG_CACHE_HOME` set | `$XDG_DATA_HOME/hashcat/sessions/`     | `$XDG_CACHE_HOME/hashcat/kernels/`    | `$XDG_DATA_HOME/hashcat/`              |
| Only `$XDG_DATA_HOME` set                  | `$XDG_DATA_HOME/hashcat/sessions/`     | `$HOME/.cache/hashcat/`               | `$XDG_DATA_HOME/hashcat/`              |
| Only `$XDG_CACHE_HOME` set                 | `$HOME/.local/share/hashcat/sessions/` | `$XDG_CACHE_HOME/hashcat/kernels/`    | `$HOME/.local/share/hashcat/`          |
| None of the above                          | `$HOME/.local/share/hashcat/sessions/` | `$HOME/.cache/hashcat/`               | `$HOME/.local/share/hashcat/`          |

---
## 🔥 Building Hashcat for Android

See: [BUILD_Android.md](BUILD_Android.md)

---

## 🐳 Building Hashcat with Docker

See: [BUILD_Docker.md](BUILD_Docker.md)

---

## 🪟 Building Hashcat for Windows

| Method                                 | Documentation                        |
|----------------------------------------|--------------------------------------|
| From macOS                             | [BUILD_macOS.md](BUILD_macOS.md)     |
| Using Windows Subsystem for Linux (WSL)| [BUILD_WSL.md](BUILD_WSL.md)         |
| Using Cygwin                           | [BUILD_CYGWIN.md](BUILD_CYGWIN.md)   |
| Using MSYS2                            | [BUILD_MSYS2.md](BUILD_MSYS2.md)     |
| From Linux                             | Run: `make win`                      |

---

## 🎉 Done

Enjoy your fresh **Hashcat** binaries! 😎
