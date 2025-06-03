import sys
import hcshared
import multiprocessing
import math

def child(qi,qo,salts,st_salts,user_fn):
  while True:
    entry = qi.get()
    if entry is None:
      break
    salt_id, passwords, is_selftest = entry
    if is_selftest:
      salt = st_salts[salt_id]
    else:
      salt = salts[salt_id]
    hashes = []
    for password in passwords:
      try:
        hashes.append(user_fn(password,salt))
      except Exception as e:
        print (e, file=sys.stderr)
        hashes.append("invalid-password")
    qo.put(hashes)
  return    

def handle_queue(ctx: dict,passwords: list,salt_id: int,is_selftest: bool) -> list:
  npasswords = len(passwords)
  if(npasswords == 0): return []
  nprocs = ctx["nprocs"]
  qos = ctx["qos"]
  qis = ctx["qis"]
  batchsize = int((npasswords+(nprocs-1))/nprocs) # round up, to garantee none of the procs are called more than once per invocation
  child_ids = math.ceil(npasswords/batchsize)     # relevant if npasswords < batchsize
  slice_start = 0
  slice_stop = slice_start+batchsize
  for child_id in range(child_ids):
    qos[child_id].put([salt_id, passwords[slice_start:slice_stop], is_selftest])
    slice_start = slice_stop
    slice_stop = slice_start+batchsize
  hashes = []
  for child_id in range(child_ids):
    hashes.extend(qis[child_id].get())
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
  # Use native cpu count
  nprocs = multiprocessing.cpu_count()
  procs = []
  qis = []
  qos = []
  multiprocessing.set_start_method('spawn', force=True)
  for child_id in range(nprocs):
    qi = multiprocessing.Queue(1)
    qis.append(qi)
    qo = multiprocessing.Queue(1)
    qos.append(qo)
    proc = multiprocessing.Process(target=child, args=(qo,qi,salts,st_salts,user_fn))  # note qi/qo side switch!
    proc.start()
    procs.append(proc)
  ctx.update ({ "nprocs": nprocs, "procs": procs, "qis": qis, "qos": qos, "salts": salts, "st_salts": st_salts })
  return

def term(ctx: dict):
  nprocs = ctx["nprocs"]
  procs = ctx["procs"]
  qos = ctx["qos"]
  for child_id in range(nprocs):
    qos[child_id].put(None)
  for child_id in range(nprocs):
    procs[child_id].join()
  return
