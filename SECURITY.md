# Security Policy

## Threat Model

hashcat is a local password recovery tool. Whoever runs it provides all of
its inputs: the hash file, wordlists, rule files (including inline `-j`/`-k`
rules), masks and custom charsets, and the session/potfile/config files.

All of that input is trusted. It comes from the same person running the
process, and it is parsed with that person's own privileges. There is no
remote attacker in the picture, nothing runs with elevated rights, and there
is no sandbox to escape. Reading a file you chose to load does not cross a
privilege boundary.

## Out of Scope

These are not treated as security vulnerabilities, because they require you
to feed malicious input to your own process:

- Crashes, out-of-bounds access, or memory corruption from a crafted rule
  file or inline `-j`/`-k` rule.
- The same from a crafted hash file, wordlist, mask, charset, or any other
  input file you load.
- Memory, disk, or CPU exhaustion caused by input you chose to load.

If someone can get you to load a malicious rule or hash file, they can just
as easily get you to run a malicious binary, so we treat the file-parsing
surface as outside the threat model. Bugs of this kind are handled as normal
robustness issues, not as security advisories, and we'd ask that you not file
them as CVEs against hashcat.

We do still want fixes for them. Bounds checks, length validation, and
rejecting malformed input cleanly are all welcome as ordinary bug fixes.

## In Scope

Things that do cross a trust boundary, for example:

- An input file or network resource that makes hashcat execute code or write
  files outside what the documented options allow (path traversal in an
  output or session path, command injection through a config value, and the
  like).
- Privilege escalation, or one local user being able to interfere with a
  hashcat process owned by another user.
- Anything in the networked or multi-user features, such as the brain server
  (`--brain-server` / `--brain-client`), where the data really does come from
  somebody else.

## Reporting a Vulnerability

Please report in-scope issues privately. Don't open a public issue or pull
request for them.

The preferred way is a GitHub private security advisory, opened from the
repository's Security tab under Advisories ("Report a vulnerability"). That
keeps things private until a fix is ready.

It helps if you include a description and impact, the affected version
(`hashcat --version`), steps to reproduce or a proof of concept, and any fix
you'd suggest.

We'll confirm we received the report, work with you on validating and fixing
anything in scope, and sort out disclosure timing together.
