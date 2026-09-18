# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through the **Security** tab of this repository using **Report a vulnerability**. This creates a private draft advisory that is visible only to you and the maintainers while the issue is investigated and fixed. If you cannot use GitHub, email security@hashcat.net instead. Plain email is not encrypted.

Please include enough information to reproduce the problem:

* the hashcat version or commit
* the exact command line
* the input required to trigger the issue
* the observed behavior
* AddressSanitizer or similar output, if available

A working reproducer is much more useful than a description of one. Reports produced by scanners, fuzzers or language models are welcome, but please verify that the issue actually reproduces before submitting it.

We will acknowledge that the report was received. If you hear nothing within seven days, the report probably did not arrive. Try the other reporting channel. Hashcat is maintained by a small number of people, so we cannot promise response times or a remediation schedule beyond the acknowledgment. Please do not open a public issue for something you believe is exploitable.

You are free to publish your findings 90 days after reporting them, whether or not a fix exists by then. When a report made through the channels above is confirmed as a vulnerability and fixed, we publish a security advisory on this repository. It credits the reporter unless they prefer not to be named. Bugs that do not cross the boundary described below are fixed without an advisory, and we do not audit past fixes to look for ones that should have had one.

## What counts as a vulnerability

The important security boundary is between the person running hashcat and input controlled by somebody else. The question is:

**Can somebody other than the person running hashcat use hashcat to harm that user?**

If the answer is yes, the issue may be a vulnerability. If the only person controlling the input is the person running hashcat, it is normally a bug rather than a vulnerability. Hashcat is not designed to protect itself from its own user. That user already controls its command line, its input files and the privileges under which it runs.

Hashcat runs as a single process with the privileges of the user who started it. It does not require root or sudo, does not install a service and does not provide a sandbox. It does not listen on a network socket unless brain functionality is explicitly enabled.

## Instructions, code and data

To apply the boundary, hashcat input falls into three categories: instructions, code and data.

Instructions are the command line and bridge parameters. They are supplied by the user, and hashcat executing them is not a security boundary violation. Bridge parameters such as `--bridge-parameter1` through `--bridge-parameter4` mean whatever the loaded bridge defines. The Python bridge, for example, runs the script named by its first parameter. That is its purpose. Supplying a bridge parameter is the same trust decision as loading the bridge.

Code means modules, bridges, feeds and kernels. A module, a bridge or an attack mode 8 feed plugin is a shared library loaded into the hashcat process. A kernel is source code compiled for and executed on the compute device. Loading any of these is the same trust decision as running a program. A bridge that starts an external tool as part of its documented function is doing its job, not crossing a security boundary. **Do not load modules, kernels, bridges or feeds from an untrusted source.**

Everything else hashcat reads is data: hash files, potfiles, wordlists, rule files, masks, restore files and every input format not named in this document. Input formats added in future versions are data unless this document explicitly names them as instructions or code. Being named on the command line does not turn a data file into instructions. A wordlist is selected on the command line and its contents remain data.

Data controls what hashcat computes. It must never decide what hashcat executes. If crafted data can make hashcat run attacker-controlled code or corrupt its memory, that is a vulnerability, even though hashcat runs locally. Data files are exactly the kind of input that users routinely download from third parties. The same rule covers remote input handled by the brain, in both directions. The server parses input from clients. A client parses input from the server it connects to.

Information disclosure crosses the boundary too. If crafted data can make hashcat put unrelated memory or file contents into its output, that is a vulnerability. Resource exhaustion through a local data file does not cross it. A crafted file that makes hashcat hang or consume all memory is a bug we want reported, but the user started the process, can watch it and can stop it. Costing the user time does not give the attacker anything. The brain server is the exception. A remote peer that can exhaust its resources before authentication completes is inside the boundary.

A restore file stores the command line of an interrupted session. `--restore` does not execute it. It prints the stored command line and exits. The printed line is quoted. Bytes outside printable ASCII are escaped. The user decides whether to run it. A crafted restore file that can exploit the parser, break the quoting or disguise what is printed is inside the boundary. **Read the printed command line before you run it.**

`--restore-auto` resumes in one step instead and executes the stored command line. Supplying that flag is the trust decision, like loading a bridge. **Do not use `--restore-auto` with a restore file from an untrusted source.**

Some data formats are expressive. A rule file is a small program in the rule language. That does not turn it into code in the sense above. The rule engine may only transform and reject password candidates. A rule file, however complex, must stay inside that function. If a crafted rule file can escape the rule engine, that is a vulnerability.

## Bugs are still bugs

This classification does not mean that other bugs are ignored. Crashes, memory corruption, hangs and incorrect results should be fixed regardless of where their input came from. A crash caused entirely by an option supplied by the user is still a bug and should still be reported. This policy answers a narrower question: whether hashcat failed to protect its user from input controlled by somebody else.

## Severity

Calling something a vulnerability does not determine its severity.

Outside the brain, hashcat normally processes local input that the user deliberately supplied. An attacker must first cause the user to run hashcat on that input. Code execution gained this way has the same privileges the user already gave to the hashcat process. There is no privilege boundary or sandbox being crossed.

For CVSS, issues of this kind are generally local and require user interaction. They should not be scored as remote or as a privilege escalation unless the specific issue actually provides those properties. Being local and requiring user interaction limits how an attack reaches hashcat. It does not make the outcome small. Code execution through a crafted data file still gives the attacker everything the user can do. The impact part of a score should reflect that.

We may therefore agree that a finding is a vulnerability while disagreeing with a severity score that does not match how hashcat is reached or what privileges it has.

## The brain

The brain is the one part of hashcat that can receive input directly from another machine. It is disabled by default, enabled only by options such as `--brain-server` or `--brain-client`, and does not require elevated privileges.

The protocol is intentionally simple. The server sends a 32 bit challenge. The client responds with an iterated `SHA-256` of the challenge followed by the brain password. The brain password is the shared secret set with `--brain-password`. If none is given, the server generates one and prints it at startup. This is a stretched challenge response, not a cryptographic message authentication code. After authentication, the protocol exchanges 64 bit candidate hashes, keyspace positions and an identifier derived from the hash list. Plaintext candidates and the hashes being cracked are not transmitted.

The protocol provides no encryption or transport integrity. A party able to observe or modify the connection can read or change the traffic. Modified traffic can interfere with deduplication and cause candidates to be skipped. If `--brain-host` is not given, the server listens on all interfaces. This may be appropriate on an isolated cracking network. Do not expose it directly to an untrusted network. **If brain traffic must cross a network you do not control, use a VPN, SSH tunnel or another trusted encrypted transport.**

These protocol properties are part of the design and are not themselves vulnerabilities. That includes the authentication. A party that observed a handshake can attack the brain password offline. The response is stretched by a fixed iteration count, but there is no memory hardness and the only salt is the observed challenge, so this is far weaker than a password hashing function. Recovering it that way and connecting later is a consequence of the design, not an authentication bypass. The transport advice above is the mitigation. Memory safety issues, real authentication bypasses and similar implementation defects are different, in the server and in the client alike. In particular, an issue reachable by a remote peer before authentication completes is within hashcat's security boundary.

## CVE identifiers

Hashcat is not a CVE Numbering Authority. When a report falls within the security boundary described above, we will treat it as a vulnerability, work on a fix and cooperate with the organization assigning a CVE identifier. When a report does not cross that boundary, we will classify it as a bug and explain why. If a CVE has been requested or assigned for such an issue, we may ask for the record to be rejected, corrected or marked disputed.

This is not a veto over the CVE process. An identifier can still be assigned after we disagree. The purpose of this policy is to make hashcat's security boundary explicit so that those discussions start from a documented position.

## Supported versions

Security fixes are developed on master and included in the next release. Older releases are not patched, and hashcat does not maintain separate security or maintenance branches for previous releases.
