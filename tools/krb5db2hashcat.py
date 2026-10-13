#!/usr/bin/env python3

# Script to turn the Kerberos keys of a domain database into hashcat lines, for modes 38400,
# 38401, 38402, 28800 and 28900

#
# Author......: See docs/credits.txt
# License.....: MIT
#

"""Turns Kerberos keys taken out of a domain database into hashcat lines.

Four input shapes are understood.

mimikatz, from `lsadump::dcsync /user:someone` or `lsadump::lsa /inject`, which prints the salt
next to the keys:

    SAM Username         : someone
     * Kerberos-Newer-Keys
        Default Salt : EXAMPLE.COMsomeone
        Default Iterations : 4096
        Credentials
          aes256_hmac       (4096) : <64 hex>
          aes128_hmac       (4096) : <32 hex>
          des_cbc_md5       (4096) : <16 hex>

the Kerberos key lines of impacket `secretsdump.py`, and of `gosecretsdump`, which writes the same
shape; they carry no salt, so the realm has to be given with --realm:

    someone:des-cbc-md5:<16 hex>

DSInternals, from `Get-ADDBAccount` or `Get-ADReplAccount`, which puts the encryption type on a
line of its own and the salt after the keys:

    SamAccountName: someone
        Kerberos:
          Credentials:
            DES_CBC_MD5
              Key: <16 hex>
          Salt: EXAMPLE.COMsomeone

and ntdissector, one JSON record per line, which carries the realm in the user principal name:

    {"sAMAccountName": "someone", "userPrincipalName": "someone@example.com",
     "supplementalCredentials": {"Primary:Kerberos-Newer-Keys": ["des-cbc-md5:<16 hex>"]}}

The salt of a Kerberos key is the realm in upper case followed by the principal, with no separator,
and the hashcat line wants the two apart. Where a salt is printed the realm is what is left of it
once the principal is taken off its end; a salt that does not end in the principal is reported and
skipped, because nothing in the output says what the rest of it is.

mimikatz and DSInternals also print the keys of the passwords before the current one, under
"OldCredentials" and "OlderCredentials". Those are named in a warning and left out unless
--history asks for them, so a cracked line is the password the account has now.

The trailing "$" of an account name marks a machine, trust or group managed service account, whose
password the machine generated and rotates, so no wordlist and no mask reaches it. Those keys are
named in a warning and left out unless --machine-keys asks for them. Their salt is not the realm
and the account name: a machine account takes "host" and the host name in the DNS domain, and a
trust account the flat name of the other side. Both are reproduced from the account name, so with
--machine-keys the key goes out under the salt a printed Default Salt agrees with, or under both
when nothing in the output says which it is.

A trust key, which secretsdump labels with the other realm and the direction of the trust, is
salted with the two realms around "krbtgt" and is written out under that name.

No tool has a name for every encryption type a database can hold, and each falls back to the
number: secretsdump prints it in hex and gosecretsdump in decimal. Both are read, as are the three
spellings the tools use for a type they do name.
"""

import argparse
import json
import re
import sys

# hashcat mode per encryption type, with the names the tools print for it, lower cased and with
# the dashes some of them use folded to underscores. "dec_cbc_crc" is impacket's spelling of
# des-cbc-crc.

ETYPES = {
  1:  ("des_cbc_crc", "dec_cbc_crc"),
  2:  ("des_cbc_md4",),
  3:  ("des_cbc_md5",),
  17: ("aes128_hmac", "aes128_cts_hmac_sha1_96"),
  18: ("aes256_hmac", "aes256_cts_hmac_sha1_96"),
}

KEY_LEN = {1: 16, 2: 16, 3: 16, 17: 32, 18: 64}

NAME_TO_ETYPE = {name: etype for etype, names in ETYPES.items() for name in names}


def etype_of(name):
  """Gives back the encryption type a label stands for, or None."""

  folded = name.lower().replace("-", "_")

  if folded in NAME_TO_ETYPE:
    return NAME_TO_ETYPE[folded]

  try:
    etype = int(name, 16) if name.startswith("0x") else int(name, 10)
  except ValueError:
    return None

  return etype if etype in ETYPES else None

# mimikatz and DSInternals put the keys of the current password under "Credentials" and
# "ServiceCredentials" and those of the passwords before it under "OldCredentials" and
# "OlderCredentials", the one printing the title bare and the other with a colon

RE_GROUP = re.compile(r"^\s+(Credentials|OldCredentials|OlderCredentials|ServiceCredentials):?\s*$")

HISTORY_GROUPS = ("OldCredentials", "OlderCredentials")

# lsadump::dcsync names the account on a "SAM Username" line, lsadump::lsa /inject on a "User" one

RE_USER = re.compile(r"^(?:SAM Username|User)\s*:\s*(\S+)\s*$")
RE_SALT = re.compile(r"^\s*Default Salt\s*:\s*(\S+)\s*$")
RE_KEY  = re.compile(r"^\s+(\S+)\s*(?:\(\d+\)\s*)?:\s*([0-9a-fA-F]+)\s*$")

# secretsdump writes the account bare, or with a domain in front of a backslash. The domain is the
# realm where it carries a dot, and the short NetBIOS name where it does not.

RE_SDMP = re.compile(r"^(?:([^:\\]+)\\)?([^:\\]+):([a-z0-9-]+):([0-9a-fA-F]+)\s*$")

# a trust key is labelled with the other realm and the direction of the trust instead of with a
# principal, and its salt is the two realms around "krbtgt"

RE_TRUST = re.compile(r"^(\S+) \((Incoming|Outgoing)(?:, previous)?\)$")

# DSInternals puts the encryption type on a line of its own with the key under it, and the salt
# after the keys rather than before, so its keys are held back until the salt turns up

RE_DSI_USER  = re.compile(r"^SamAccountName:\s*(\S+)\s*$")
RE_DSI_ETYPE = re.compile(r"^\s+([A-Z][A-Z0-9_]+)\s*$")
RE_DSI_KEY   = re.compile(r"^\s+Key:\s*([0-9a-fA-F]+)\s*$")
RE_DSI_SALT  = re.compile(r"^\s+Salt:\s*(\S+)\s*$")


def emit(out, user, realm, etype, key, where, warn):
  if len(key) != KEY_LEN[etype]:
    warn("%s: %s key is %d hex characters, expected %d, skipped" % (where, ETYPES[etype][0], len(key), KEY_LEN[etype]))
    return 0

  if "$" in user or "$" in realm:
    warn("%s: '$' in %r or %r, which the hash line is cut on, skipped" % (where, user, realm))
    return 0

  if " " in user or " " in realm:
    warn("%s: a space in %r or %r, which no principal carries, skipped" % (where, user, realm))
    return 0

  line = "$krb5db$%d$%s$%s$%s" % (etype, user, realm, key.lower())

  # a key under two headings is one key: mimikatz prints the DES one under Kerberos-Newer-Keys
  # and again under Kerberos, and DSInternals under KerberosNew and again under Kerberos

  if line in out:
    return 0

  out.append(line)
  return 1


def machine_principals(name, realm):
  """Gives back the principals whose salt a machine or trust account key may have.

  secretsdump and Rubeus build the two the same way, a computer account as {REALM}host{host}.{realm}
  and a trust account as {REALM}krbtgt{FLAT}, so both are reproduced from the account name alone.
  """

  return ["host%s.%s" % (name.lower(), realm.lower()), "krbtgt%s" % name.upper()]


def machine_realm(salt, name):
  """Gives back the realm of a machine or trust account salt, or None when neither shape fits."""

  tail = "krbtgt%s" % name.upper()

  if salt.endswith(tail) and len(salt) > len(tail):
    return salt[:len(salt) - len(tail)]

  # {REALM}host{host}.{realm} carries the realm twice, so its length gives the length of the realm

  realm_len, odd = divmod(len(salt) - len("host.") - len(name), 2)

  if odd == 0 and realm_len > 0:
    realm = salt[:realm_len]

    if salt == "%shost%s.%s" % (realm.upper(), name.lower(), realm.lower()):
      return realm

  return None


def split_salt(salt, user, where, warn):
  """Gives back the realm of a salt, or None when it cannot be read off."""

  if user and salt.lower().endswith(user.lower()) and len(salt) > len(user):
    return salt[:len(salt) - len(user)]

  if user.endswith("$"):
    realm = machine_realm(salt, user[:-1])

    if realm is not None:
      return realm

  warn("%s: salt %r does not end in the principal %r, pass --realm to set the realm" % (where, salt, user))
  return None


def emit_account(out, user, realm, etype, key, salt, machine, where, warn):
  """Writes a key out under every salt its account may have been derived with."""

  if not user.endswith("$"):
    return emit(out, user, realm, etype, key, where, warn)

  # the trailing '$' marks an account whose password the machine generated and rotates, a computer,
  # a trust or a group managed service account, so no wordlist and no mask reaches it

  if not machine:
    warn("%s: %r is a machine or trust account, whose password is machine generated; pass --machine-keys to write it out anyway" % (where, user))
    return 0

  principals = machine_principals(user[:-1], realm)

  # a printed salt settles which of the two shapes the key came from

  if salt:
    principals = [p for p in principals if (realm.upper() + p) == salt]

    if not principals:
      warn("%s: salt %r is not the one a machine or trust account named %r would have, skipped" % (where, salt, user))
      return 0
  else:
    warn("%s: %r is a machine or trust account and the output does not say which, so the key is written under both salts" % (where, user))

  return sum(emit(out, p, realm, etype, key, where, warn) for p in principals)


def parse_mimikatz(lines, realm_opt, machine, history, warn):
  out = []
  user = None
  salt = None
  group = None

  for n, line in enumerate(lines, 1):
    m = RE_USER.match(line)
    if m:
      user = m.group(1)
      salt = None
      group = None
      continue

    m = RE_GROUP.match(line)
    if m:
      group = m.group(1)
      continue

    m = RE_SALT.match(line)
    if m:
      salt = m.group(1)
      continue

    m = RE_KEY.match(line)
    if m is None:
      continue

    etype = etype_of(m.group(1))
    if etype is None:
      continue

    where = "line %d" % n

    if user is None:
      warn("%s: a key before any 'SAM Username' line, skipped" % where)
      continue

    if group in HISTORY_GROUPS and not history:
      warn("%s: a key of %s under %s, which is a password before the current one; pass --history to write it out" % (where, user, group))
      continue

    realm = realm_opt or (split_salt(salt, user, where, warn) if salt else None)

    if realm is None:
      if salt is None:
        warn("%s: no 'Default Salt' seen for %s, pass --realm" % (where, user))
      continue

    emit_account(out, user, realm, etype, m.group(2), salt, machine, where, warn)

  return out


# secretsdump and gosecretsdump read only the current set out of the stored credential, so this
# takes the history flag to keep one signature across the four parsers and has nothing to do with it

def parse_secretsdump(lines, realm_opt, machine, history, warn):
  out = []

  # A run targets one domain, so a realm written on any line serves the lines that carry none. Only
  # one realm may be in play: two would make the choice a guess, and a wrong salt cracks nothing.

  if realm_opt is None:
    seen = {m.group(1).upper() for m in (RE_SDMP.match(l) for l in lines)
            if m is not None and m.group(1) and "." in m.group(1) and etype_of(m.group(3))}

    if len(seen) == 1:
      realm_opt = seen.pop()
      warn("no --realm given, using %r, the realm the file itself carries" % realm_opt)
    elif len(seen) > 1:
      warn("the file carries more than one realm (%s), pass --realm to pick one" % ", ".join(sorted(seen)))

  for n, line in enumerate(lines, 1):
    m = RE_SDMP.match(line)
    if m is None:
      continue

    prefix, user, etype_name, key = m.groups()

    etype = etype_of(etype_name)
    if etype is None:
      continue

    where = "line %d" % n

    realm = realm_opt

    if realm is None and prefix:
      if "." not in prefix:
        warn("%s: %r is a NetBIOS name, not a realm, and the salt is built from the realm; pass --realm" % (where, prefix))
        continue

      realm = prefix.upper()

    if realm is None:
      warn("%s: no realm in the line, pass --realm" % where)
      continue

    m = RE_TRUST.match(user)

    if m:
      # the local realm comes first for an incoming trust and the other one for an outgoing one

      partner = m.group(1)

      if m.group(2) == "Incoming":
        user, realm = "krbtgt" + partner.upper(), realm
      else:
        user, realm = "krbtgt" + realm.upper(), partner

    emit_account(out, user, realm, etype, key, None, machine, where, warn)

  return out


def parse_dsinternals(lines, realm_opt, machine, history, warn):
  out = []
  user = None
  etype = None
  group = None
  pending = []

  def flush(salt):
    realm = realm_opt

    if realm is None and salt:
      realm = split_salt(salt, user, pending[0][2], warn) if pending else None

    for e, key, where in pending:
      if realm is None:
        warn("%s: no 'Salt' line seen for %s, pass --realm" % (where, user))
        continue

      emit_account(out, user, realm, e, key, salt, machine, where, warn)

    pending.clear()

  for n, line in enumerate(lines, 1):
    m = RE_DSI_USER.match(line)
    if m:
      flush(None)
      user = m.group(1)
      group = None
      continue

    m = RE_GROUP.match(line)
    if m:
      group = m.group(1)
      continue

    m = RE_DSI_SALT.match(line)
    if m:
      flush(m.group(1))
      continue

    m = RE_DSI_ETYPE.match(line)
    if m:
      etype = etype_of(m.group(1))
      continue

    m = RE_DSI_KEY.match(line)
    if m is None:
      continue

    if etype is None:
      continue

    if user is None:
      warn("line %d: a key before any 'SamAccountName' line, skipped" % n)
      continue

    if group in HISTORY_GROUPS and not history:
      warn("line %d: a key of %s under %s, which is a password before the current one; pass --history to write it out" % (n, user, group))
      continue

    pending.append((etype, m.group(1), "line %d" % n))

  flush(None)

  return out


# ntdissector reads only the current set as well, so the history flag is here for the signature

def parse_ntdissector(lines, realm_opt, machine, history, warn):
  out = []

  for n, line in enumerate(lines, 1):
    line = line.strip()

    if not line.startswith("{"):
      continue

    try:
      rec = json.loads(line)
    except ValueError:
      continue

    if not isinstance(rec, dict):
      continue

    creds = rec.get("supplementalCredentials")

    if not isinstance(creds, dict):
      continue

    user = rec.get("sAMAccountName") or rec.get("name")

    if not user:
      warn("line %d: a record with no account name, skipped" % n)
      continue

    where = "line %d" % n

    # the realm is not in a salt of its own, it is the tail of the user principal name

    realm = realm_opt

    if realm is None:
      upn = rec.get("userPrincipalName") or ""

      if "@" in upn:
        realm = upn.rsplit("@", 1)[1].upper()

    if not realm:
      warn("%s: no realm for %s, which a record carries only in a user principal name, pass --realm" % (where, user))
      continue

    for group in ("Primary:Kerberos-Newer-Keys", "Primary:Kerberos"):
      for item in creds.get(group) or []:
        if not isinstance(item, str):
          continue

        label, sep, key = item.partition(":")

        if not sep:
          continue

        etype = etype_of(label)

        if etype is None:
          continue

        emit_account(out, user, realm, etype, key, None, machine, where, warn)

  return out


def main():
  ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
  ap.add_argument("file", help="path to the mimikatz, secretsdump or DSInternals output, - to read stdin")
  ap.add_argument("-r", "--realm", help="realm to use, required where the output carries no salt")
  ap.add_argument("-e", "--etype", type=int, choices=sorted(ETYPES), action="append", help="keep only these encryption types, repeatable")
  ap.add_argument("--machine-keys", action="store_true", help="write out the keys of machine and trust accounts as well, which no wordlist reaches")
  ap.add_argument("--history", action="store_true", help="write out the keys of the passwords before the current one as well")
  args = ap.parse_args()

  try:
    with (sys.stdin if args.file == "-" else open(args.file, encoding="utf-8", errors="replace")) as f:
      lines = f.read().splitlines()
  except OSError as e:
    ap.error(e.strerror.lower() if e.strerror else str(e))

  warnings = []

  def warn(msg):
    warnings.append(msg)

  realm = args.realm.upper() if args.realm else None

  out = parse_mimikatz(lines, realm, args.machine_keys, args.history, warn)

  if not out:
    # no mimikatz block matched, so the input may be the plain user:etype:key of secretsdump
    sd_warnings = []
    sd = parse_secretsdump(lines, realm, args.machine_keys, args.history, sd_warnings.append)

    if sd or sd_warnings:
      out, warnings = sd, sd_warnings

  if not out:
    # nor that, so the input may be the block layout DSInternals prints
    ds_warnings = []
    ds = parse_dsinternals(lines, realm, args.machine_keys, args.history, ds_warnings.append)

    if ds or ds_warnings:
      out, warnings = ds, ds_warnings

  if not out:
    # nor that, so the input may be the JSON ntdissector writes, one record per line
    nd_warnings = []
    nd = parse_ntdissector(lines, realm, args.machine_keys, args.history, nd_warnings.append)

    if nd or nd_warnings:
      out, warnings = nd, nd_warnings

  if args.etype:
    keep = {"$krb5db$%d$" % e for e in args.etype}
    out = [line for line in out if any(line.startswith(k) for k in keep)]

  for line in out:
    print(line)

  for msg in warnings:
    print("warning: %s" % msg, file=sys.stderr)

  if not out:
    print("no Kerberos keys found", file=sys.stderr)
    return 1

  return 0


if __name__ == "__main__":
  sys.exit(main())
