#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

"""Linux brain correctness tests and server/filter benchmarks. Run make first."""

import argparse
import array
import concurrent.futures
import contextlib
import ctypes
import hashlib
import mmap
import os
from pathlib import Path
import random
import re
import shlex
import signal
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parent.parent
SESSION = 1


def build(path):
    objects = sorted(p for p in (ROOT / "obj").glob("*.NATIVE.o")
                     if p.name != "brain.NATIVE.o")
    if not objects:
        raise RuntimeError("Run make first")
    command = shlex.split(os.environ.get("CC", "cc")) + [
        "-std=gnu99", "-O2", "-W", "-Wall", "-Wextra",
        "-ffunction-sections", "-fdata-sections", "-DWITH_BRAIN", "-DHC_CORE_STATIC",
        "-Iinclude", "-IOpenCL", "-Ideps/OpenCL-Headers", "tools/test_brain.c",
        *map(str, objects), "-Wl,--gc-sections", "-pthread", "-ldl", "-lm",
        "-o", str(path),
    ]
    subprocess.run(command, cwd=ROOT, check=True)


def receive(sock, size):
    buf = bytearray(size)
    view = memoryview(buf)
    pos = 0
    while pos < size:
        got = sock.recv_into(view[pos:])
        if got == 0:
            raise EOFError("Brain disconnected")
        pos += got
    return buf


class Client:
    def __init__(self, port, maximum=2097152):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=120)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock.sendall(struct.pack("<I", 2))
        assert struct.unpack("<I", receive(self.sock, 4))[0] == 1
        challenge = receive(self.sock, 4)
        digest = hashlib.sha256(challenge + b"brain-test").digest()
        for _ in range(100000):
            digest = hashlib.sha256(digest).digest()
        self.sock.sendall(struct.pack("<Q", int.from_bytes(digest[:8], "big")))
        assert struct.unpack("<I", receive(self.sock, 4))[0] == 1
        self.sock.sendall(struct.pack("<IIq", SESSION, 0, maximum))
        receive(self.sock, 8)

    def lookup(self, payload):
        self.sock.sendall(struct.pack("<Bi", 2, len(payload)) + payload)
        size = struct.unpack("<i", receive(self.sock, 4))[0]
        assert size == len(payload) // 8
        return bytes(receive(self.sock, size))

    def commit(self):
        self.sock.sendall(b"\x01")

    def close(self):
        self.sock.close()


@contextlib.contextmanager
def server(exe, directory, threshold, library=None, save=True):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    log = directory / "server.log"
    with log.open("w") as output:
        if library:
            command = [sys.executable, str(Path(__file__).resolve()), "--serve-library",
                       str(Path(library).resolve()), str(port)]
        else:
            command = [str(exe), "--server", str(port), str(threshold)]
        process = subprocess.Popen(command,
                                   cwd=directory, stdout=output, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 180
            while "Brain server started" not in log.read_text():
                if process.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError(log.read_text())
                time.sleep(0.05)
            yield port, log, process.pid
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM if save else signal.SIGKILL)
                try:
                    process.wait(timeout=180)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    raise
            expected = 0 if save else -signal.SIGKILL
            if process.returncode != expected:
                raise RuntimeError(log.read_text())


def pack(keys):
    return b"".join(struct.pack("<Q", key) for key in keys)


def protocol_tests(exe, base):
    feed_input = "".join(f"brain-filter-{idx}\n" for idx in range(16384))

    def feed(port, known):
        result = subprocess.run([
            str(ROOT / "hashcat"), "--brain-feed", "--brain-session", "0x00000001",
            "--brain-host", "127.0.0.1", "--brain-port", str(port),
            "--brain-password", "brain-test",
        ], input=feed_input, text=True, capture_output=True, cwd=base, check=True)
        assert f", {known} were already known." in result.stdout, result.stdout + result.stderr

    # Low thresholds let small protocol tests exercise activation and dump reloads.
    for threshold in (0, 8):
        directory = base / f"protocol-{threshold}"
        directory.mkdir()
        keys = list(range(0, 65536, 2))
        payload = pack(keys)
        with server(exe, directory, threshold) as (port, log, _):
            client = Client(port)
            assert client.lookup(payload) == bytes(len(keys))
            assert client.lookup(payload) == b"\x01" * len(keys)
            client.commit()
            assert client.lookup(payload) == b"\x01" * len(keys)
            client.close()

            def worker(worker_id):
                other = Client(port)
                own = pack(range(65537 + worker_id * 2048, 67585 + worker_id * 2048))
                assert other.lookup(own) == bytes(2048)
                other.commit()
                assert other.lookup(own) == b"\x01" * 2048
                assert other.lookup(payload) == b"\x01" * len(keys)
                other.close()

            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                list(pool.map(worker, range(4)))

            feed(port, 0)
            deadline = time.monotonic() + 10
            while not re.search(r"C \|.*Hashes:\s+16384", log.read_text()):
                if time.monotonic() > deadline:
                    raise RuntimeError("Feed commit timed out")
                time.sleep(0.01)
            feed(port, 16384)

        with server(exe, directory, threshold) as (port, _, _):
            client = Client(port)
            assert client.lookup(payload) == b"\x01" * len(keys)
            assert client.lookup(pack([1, 1, 3, 3])) == b"\x00\x01\x00\x01"
            client.close()
            feed(port, 16384)
    assert ((base / "protocol-0" / "brain.00000001.ldmp").read_bytes()
            == (base / "protocol-8" / "brain.00000001.ldmp").read_bytes())
    print("Brain protocol, feeds, pending candidates, concurrency and dump reload: passed", flush=True)


def rss_kib(pid):
    status = Path(f"/proc/{pid}/status")
    if not status.exists():
        return None
    match = re.search(r"^VmRSS:\s+(\d+)", status.read_text(), re.M)
    return int(match[1]) if match else None


def benchmark_protocol(exe, base, count, args):
    directory = base / "benchmark"
    directory.mkdir(exist_ok=True)
    dump = directory / "brain.00000001.ldmp"
    subprocess.run([str(exe), "--dump", str(count), str(dump)], check=True)
    rng = random.Random(123456789)
    with dump.open("rb") as source, mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
        variants = [] if args.paired else [(0, None)]
        if args.baseline_library:
            variants.insert(0, (-1, args.baseline_library))
        variants.extend((threshold, None) for threshold in args.thresholds)
        for threshold, library in variants:
            # Discard benchmark commits so every variant reads the same dump.
            with server(exe, directory, threshold, library=library, save=False) as (port, log, pid):
                print(f"server entries={count} threshold={threshold} rss_kib={rss_kib(pid)}",
                      flush=True)
                enabled = True

                def set_filter(wanted):
                    nonlocal enabled
                    if enabled == wanted:
                        return
                    toggles = log.read_text().count("Filter toggled\n")
                    os.kill(pid, signal.SIGUSR1)
                    deadline = time.monotonic() + 5
                    while log.read_text().count("Filter toggled\n") == toggles:
                        if time.monotonic() > deadline:
                            raise RuntimeError("Filter toggle timed out")
                        time.sleep(0.001)
                    enabled = wanted

                for batch in args.batches:
                    for duplicates in args.duplicates:
                        # Reconnect for each sample so pending candidates do not turn
                        # an unseen benchmark into a repeat benchmark.
                        rng.seed(123456789)
                        keys = array.array("Q")
                        expected = bytearray(batch)
                        for idx in range(batch):
                            if idx % 100 < duplicates:
                                key = struct.unpack_from("<Q", data, rng.randrange(count) * 8)[0]
                                expected[idx] = 1
                            else:
                                key = rng.getrandbits(64) | 1
                            keys.append(key)
                        payload = keys.tobytes()
                        if args.paired and library is None:
                            samples = {False: [], True: []}
                            for repeat in range(args.repeats + 1):
                                order = [False, True] if repeat % 2 == 0 else [True, False]
                                for wanted in order:
                                    set_filter(wanted)
                                    client = Client(port)
                                    start = time.perf_counter()
                                    result = client.lookup(payload)
                                    duration = (time.perf_counter() - start) * 1000
                                    client.close()
                                    assert result == expected
                                    server_time = float(re.findall(
                                        r"L \|\s+([0-9.]+) ms", log.read_text())[-1])
                                    if repeat:
                                        samples[wanted].append((server_time, duration))
                            for wanted, values in samples.items():
                                print(f"paired entries={count} threshold={threshold} batch={batch} "
                                      f"duplicates={duplicates} bloom={int(wanted)} "
                                      f"server_ms={statistics.median(v[0] for v in values):.3f} "
                                      f"roundtrip_ms={statistics.median(v[1] for v in values):.3f}",
                                      flush=True)
                            changes = [(on[0] / off[0] - 1) * 100
                                       for off, on in zip(samples[False], samples[True])]
                            print(f"paired_change entries={count} threshold={threshold} "
                                  f"batch={batch} duplicates={duplicates} "
                                  f"median_pct={statistics.median(changes):.3f}", flush=True)
                            continue
                        elapsed = []
                        for repeat in range(args.repeats + 1):
                            client = Client(port)
                            start = time.perf_counter()
                            result = client.lookup(payload)
                            duration = (time.perf_counter() - start) * 1000
                            client.close()
                            assert result == expected
                            if repeat:
                                elapsed.append(duration)
                        times = [float(ms) for ms in re.findall(
                            r"L \|\s+([0-9.]+) ms", log.read_text())][-(args.repeats + 1):]
                        assert len(times) == args.repeats + 1
                        print(f"protocol entries={count} threshold={threshold} batch={batch} "
                              f"duplicates={duplicates} server_ms={statistics.median(times[1:]):.3f} "
                              f"roundtrip_ms={statistics.median(elapsed):.3f}", flush=True)

                if args.paired and library is None:
                    set_filter(True)

                def parallel_lookup(client):
                    result = client.lookup(payload)
                    client.close()
                    assert result == expected

                clients = [Client(port) for _ in range(4)]
                with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                    start = time.perf_counter()
                    list(pool.map(parallel_lookup, clients))
                    elapsed = (time.perf_counter() - start) * 1000
                print(f"concurrent entries={count} threshold={threshold} clients=4 "
                      f"batch={batch} duplicates={duplicates} elapsed_ms={elapsed:.3f}", flush=True)

                client = Client(port)
                commit_rng = random.Random(987654321)
                additions = pack(commit_rng.getrandbits(64) | 1 for _ in range(65536))
                assert client.lookup(additions) == bytes(65536)
                client.commit()
                assert client.lookup(additions) == b"\x01" * 65536
                client.close()
                commits = re.findall(r"C \|\s+([0-9.]+) ms \| Hashes:", log.read_text())
                assert commits
                print(f"commit entries={count} threshold={threshold} batch=65536 "
                      f"server_ms={commits[-1]} rss_kib={rss_kib(pid)}", flush=True)
    dump.unlink()


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "--serve-library":
        library = ctypes.CDLL(str(Path(sys.argv[2]).resolve()))
        function = library.brain_server
        function.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
                             ctypes.c_char_p, ctypes.c_uint32]
        function.restype = ctypes.c_int
        raise SystemExit(function(b"127.0.0.1", int(sys.argv[3]), b"brain-test", None, 0))

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bench", action="store_true", help="also run isolated and protocol benchmarks")
    parser.add_argument("--entries", type=int, nargs="+", default=[10000000, 100000000, 300000000])
    parser.add_argument("--thresholds", type=int, nargs="+", default=[16384, 32768, 65536, 131072, 262144])
    parser.add_argument("--batches", type=int, nargs="+", default=[65536, 262144, 1048576],
                        help="protocol benchmark batch sizes")
    parser.add_argument("--duplicates", type=int, nargs="+", choices=[0, 50, 100], default=[0, 50, 100],
                        help="protocol benchmark duplicate percentages")
    parser.add_argument("--repeats", type=int, default=7)
    parser.add_argument("--protocol-only", action="store_true", help="skip isolated benchmarks")
    parser.add_argument("--baseline-library", type=Path, help="also benchmark an original libhashcat")
    parser.add_argument("--cpu", type=int, help="pin tests and child servers to one Linux CPU")
    parser.add_argument("--paired", action="store_true", help="alternate filtering in one loaded server")
    args = parser.parse_args()
    if args.repeats < 1 or any(n < 1024 or n > 4294967296 for n in args.entries):
        parser.error("require positive repeats and 1024..4294967296 entries")
    if any(n < 1 or n > 2097152 for n in args.batches) or any(n < 1 for n in args.thresholds):
        parser.error("require batches of 1..2097152 and positive thresholds")
    if args.cpu is not None:
        os.sched_setaffinity(0, {args.cpu})
    with tempfile.TemporaryDirectory(prefix="hashcat-brain-") as tmp:
        base = Path(tmp)
        exe = base / "test_brain"
        build(exe)
        subprocess.run([str(exe)], check=True)
        protocol_tests(exe, base)
        if args.bench:
            for count in args.entries:
                if not args.protocol_only:
                    for threshold in args.thresholds:
                        subprocess.run([str(exe), "--bench", str(count), str(threshold)], check=True)
                benchmark_protocol(exe, base, count, args)
    print("Brain tests: 0 errors detected", flush=True)


if __name__ == "__main__":
    main()
