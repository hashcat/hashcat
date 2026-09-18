import importlib
import multiprocessing
import hcshared

def _worker_batch(chunk, salt_id, is_selftest, module_name, salts, st_salts, salt_per_pw=False):
    user_module = importlib.import_module(module_name)
    calc_hash = getattr(user_module, "calc_hash")
    return hcshared._worker_batch(chunk, salt_id, is_selftest, calc_hash, salts, st_salts, salt_per_pw)

def init(ctx: dict, extract_esalts):
    # Extract and merge salts and esalts
    salts = hcshared.extract_salts(ctx["salts_buf"])
    esalts = extract_esalts(ctx["esalts_buf"])
    for salt, esalt in zip(salts, esalts):
        salt["esalt"] = esalt

    st_salts = hcshared.extract_salts(ctx["st_salts_buf"])
    st_esalts = extract_esalts(ctx["st_esalts_buf"])
    for salt, esalt in zip(st_salts, st_esalts):
        salt["esalt"] = esalt

    # Save in ctx
    ctx["salts"] = salts
    ctx["st_salts"] = st_salts
    ctx["module_name"] = ctx.get("module_name", "__main__")

    ctx["pool"] = multiprocessing.Pool(processes=ctx["parallelism"])
    return

def handle_queue(ctx: dict, passwords: list, salt_id: int, is_selftest: bool) -> list:
    pool = ctx["pool"]
    salts = ctx["salts"]
    st_salts = ctx["st_salts"]
    module_name = ctx["module_name"]
    parallelism = ctx["parallelism"]

    salt_per_pw = ctx.get("salt_per_pw", False)

    chunk_size = (len(passwords) + parallelism - 1) // parallelism
    chunks = [passwords[i:i + chunk_size] for i in range(0, len(passwords), chunk_size)]

    # A worker takes a slice of the batch, so it gets the batch's start plus that slice's offset.

    jobs = []
    for chunk_idx, chunk in enumerate(chunks):
        if chunk:
            chunk_salt_id = salt_id + (chunk_idx * chunk_size if salt_per_pw and not is_selftest else 0)

            jobs.append(pool.apply_async(
                _worker_batch,
                args=(chunk, chunk_salt_id, is_selftest, module_name, salts, st_salts, salt_per_pw)
            ))

    hashes = []
    for job in jobs:
        hashes.extend(job.get())
    return hashes

def term(ctx: dict):
    if "pool" in ctx:
        ctx["pool"].close()
        ctx["pool"].join()
        del ctx["pool"]
    return
