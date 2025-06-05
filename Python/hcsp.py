import hcshared

def handle_queue(ctx: dict, passwords: list, salt_id: int, is_selftest: bool) -> list:
    user_fn = ctx["user_fn"]
    salts = ctx["salts"]
    st_salts = ctx["st_salts"]
    return hcshared._worker_batch (passwords, salt_id, is_selftest, user_fn, salts, st_salts)

def init(ctx: dict,user_fn,extract_esalts):
    # Extract and merge salts and esalts
    salts = hcshared.extract_salts(ctx["salts_buf"])
    esalts = extract_esalts(ctx["esalts_buf"])
    for salt, esalt in zip(salts, esalts):
        salt["esalt"] = esalt

    st_salts = hcshared.extract_salts(ctx["st_salts_buf"])
    st_esalts = extract_esalts(ctx["st_esalts_buf"])
    for salt, esalt in zip(st_salts, st_esalts):
        salt["esalt"] = esalt

    # Save state in ctx
    ctx["salts"] = salts
    ctx["st_salts"] = st_salts
    ctx["user_fn"] = user_fn
    return

def term(ctx: dict):
    return
