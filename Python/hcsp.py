import sys
import hcshared

def handle_queue(ctx: dict,passwords: list,salt_id: int,is_selftest: bool) -> list:
  npasswords = len(passwords)
  if(npasswords == 0): return []
  user_fn = ctx["user_fn"]
  if is_selftest:
    salt = ctx["st_salts"][salt_id]
  else:
    salt = ctx["salts"][salt_id]
  hashes = []
  for password in passwords:
    try:
      hashes.append(user_fn(password,salt))
    except Exception as e:
      print (e, file=sys.stderr)
      hashes.append("invalid-password")
  return(hashes)

def init(ctx: dict,user_fn,extract_esalts):
  # Extract salt and esalt, merge esalt into salt
  salts = hcshared.extract_salts(ctx["salts_buf"])
  esalts = extract_esalts(ctx["esalts_buf"])
  for salt,esalt in zip(salts,esalts):
    salt["esalt"] = esalt
  # Same extraction, but for self-test hash
  st_salts = hcshared.extract_salts(ctx["st_salts_buf"])
  st_esalts = extract_esalts(ctx["st_esalts_buf"])
  for salt,esalt in zip(st_salts,st_esalts):
   salt["esalt"] = esalt
  ctx.update ({ "salts": salts, "st_salts": st_salts, "user_fn": user_fn })
  return

def term(ctx: dict):
  return
