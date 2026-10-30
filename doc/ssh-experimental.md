# Experimental SSH: Checkpoint 5E

**Experimental / lab use only — not production-ready.**

This contribution extends DrDoof (d00f)'s existing experimental SSH/crypto work
on DrDoof/RTLPlayground, branch test/ssh. The common baseline is
ab2af23a182789d9b4f0c6e162dc91694b580e58. It is not a replacement SSH stack or
an integration into upstream main. Original implementation and attribution remain
in the branch ancestry. Adapted production commits retain their authors, dates
and Original-commit trailers; local research histories and artifacts are omitted.

Production files match the hardware-trial Checkpoint 5E source
33b9bc21f408bb887f45753a6091a161a8784bb9. The clean branch changes test
orchestration/documentation, not that production candidate.

## Changes relative to DrDoof's SSH branch

- Constant-scan Ed25519 fixed-base comb and streamed X25519 constant-multiply
  columns; SHA-256 round temporaries reduce its assembly-derived stack use by
  17 bytes without new shared workspace.
- Bounded packet/string/name-list parsing, four-byte wire-length checks before
  narrowing, padding/boolean/channel validation, queue reservations and
  fail-closed packet sequence/window overflow handling.
- SDCC overlay allocation repair using leaf decoders, preserving validation.
- Separate bounded SSH command output from HTTP outbuf/slen. Retain immutable
  outgoing ciphertext until exact TCP ACK or terminal cleanup; retransmission
  does not advance cipher/sequence state. Reject conflicting shell/exec/PTY use.
- HTTP owner/generation lifecycle fences through closing/reuse, absolute SSH
  phase/fragment/output-stall deadlines, and actual uIP retry-path terminal cleanup.

## Algorithms and capabilities (source-verified)

The existing protocol advertises curve25519-sha256 key exchange, ssh-ed25519
host signatures, chacha20-poly1305@openssh.com authenticated encryption in both
directions, and no compression. There is no separate negotiated HMAC with this
AEAD. Password authentication, one session channel, bounded PTY requests,
interactive shell and exec reach the firmware CLI. This is not a general SSH
server: there is no SFTP/SCP or port-forwarding implementation.

SSH=1 leaves two total uIP TCP slots, shared by HTTP and SSH; there is one SSH
engine/owner, not two simultaneous SSH sessions. Command capture is bounded to
2500 bytes; flight snapshot to the target MSS1460. Ownership assumes synchronous
foreground callbacks and commands that do not yield into transport processing.

The existing generic uIP idle policy also applies to authenticated SSH:
UIP_CONF_IDLE_PERIODS=200 and UIP_CONF_IDLE_TIMEOUT=30. At nominal200Hz,
a silent established connection with no unacknowledged output is reset around
30 seconds. It counts serviced foreground sweeps rather than absolute time;
coalesced ticks can delay it. Valid peer traffic can reset its idle counter.
The physical31.079-second observation is consistent with that policy, not an
independently validated SSH-08 PASS. Its expectation and client keepalive settings
must be reviewed before classifying that test.

## Reproduction and validation

Target build (existing Makefile; SDCC4.6.0 #16555 was used for the retained build):

~~~sh
make -j2 MACHINE=SWTGW218AS SSH=1 HEALTH= CI=0
~~~

Select the established SDCC/sdas8051 binaries with CC/ASM when needed. This is a
production-mode SSH build without diagnostic instrumentation. The historical
build additionally fixed GIT_VERSION=ssh-crypto-pair and
SOURCE_DATE_EPOCH=1792969186; a later build need not have an identical binary
hash because packaging/version inputs can differ.

Portable offline tests require GCC, Clang ASan/UBSan, make, Python cryptography
and OpenSSH. Sockets in the localhost suite bind only to127.0.0.1:

~~~sh
python3 test/ssh_host/run_regression.py
# Optional explicit new libFuzzer campaign:
python3 test/ssh_host/run_regression.py --fuzz-runs 50000
~~~

The portable runner reproduces parser/deterministic fuzz, output ownership,
actual-uIP integration, crypto differential/RFC8032, SHA streaming, OpenSSH
loopback and existing subsystem tests. Host crypto uses a portable field backend;
it does not validate target assembler or RTL8373 interrupt behavior. Packet
integration uses actual uIP/HTTP/SSH port code with hardware edges mocked and an
authenticated SSH state seeded to isolate transport ownership; separate native
OpenSSH exchanges cover KEX/signatures/encrypted authentication failure.

Retained Checkpoint 5E evidence: SDCC target link PASS with no final warnings;
907 parser assertions and20000 deterministic cases;50000 LibFuzzer runs
(coverage664, corpus167);31 ownership assertions;24 integrated transport checks;
2356 crypto differential cases per native/sanitized run; RFC8032 vectors;
four sequential OpenSSH loopback exchanges; existing HTTP/subsystem regressions.
SHA streaming has84 differential chunk/vector cases including million-a.
The clean contribution's portable runner was also executed successfully; the
completed50000-run fuzz campaign was reused rather than repeated unnecessarily.
Full local research logs, generated binaries/maps and lab-specific scripts are
excluded from the contribution.

Retained target allocation: initial SP0x79; stack0x7a..0xff (134 bytes);
ordinary DATA101 cells; OSEG8 at0x72..0x79; static XDATA24202 bytes; BANK1
margin484 bytes. Linker allocation and positive modeled margins are not runtime
stack safety proofs. No accepted interrupt-inclusive stack maximum is available.

## Hardware observations (one unit, operator-reported)

HORACO SWTGW218AS / RTL8373, firmware v0.1.0-ssh-crypto-pair. Supplied512KiB
image SHA-256:

~~~text
53da26096710df8abaeb4b6b2b779baf040e83822598c93e0d1b26a0b80ac598
~~~

This is the supplied image hash, not a readback attestation of installed flash.
The operator reports eight successful checks covering TCP connect, KEX/host key,
password authentication, read-only command execution, reconnect,
invalid-password rejection, SSH/HTTP coexistence and TCP reconnect. The separate
idle session closed after31.079 seconds while HTTP remained responsive; it is
not independently classified PASS here.

SwitchLab0.8.2 reported15 successful checks, including Ethernet forwarding and
stability. Overall acceptance remained BLOCKED by generator/evidence limitations
and incomplete checks. The two Ethernet ERROR cases had zero measured packet
loss but generator C→A rates below the requested tolerance. Continuous UART
capture failed; later runtime/reset coverage was incomplete. This is neither
proof of a confirmed firmware forwarding defect nor a whole-device acceptance.
Paced Ethernet results do not establish wire-rate performance or SSH stack safety.
No additional device testing was performed while preparing this contribution.

## Security limitations and outstanding work

- **Shared hardcoded development host key.** crypto/ed25519_consts.h contains the
  expanded private scalar/prefix and public key; ed25519.c uses these compiled
  constants. They are unchanged from DrDoof's already-public baseline. Every
  image using them shares an impersonable identity. They are not a newly
  introduced deployment secret; do not use them for a trusted host identity.
- **RNG security unestablished.** ssh_port_random uses get_random_32, which enables
  the RLDP random source and reads RTL837X_RAND_NUM0. There is no established
  cryptographic entropy/health/conditioning proof. This PR does not change it.
- **No implemented/validated rekey lifecycle.** The KEX state machine is for the
  initial exchange; packet sequence exhaustion fails closed. There is no validated
  long-session key/byte/time rekey policy.
- **Stack/IRQ bound incomplete.** Foreground prototype97 bytes (state-restricted91)
  is not an exhaustive interrupt-inclusive bound. Exact RTL8373 IRQ priority,
  nesting/reset contract and full-path proof remain unresolved. No production
  stack-admission guard from later offline fixtures is included.
- **Experimental authentication/command authority.** Production password checking
  compares the configured shared passwd[]; the parsed username does not select an
  authorization identity. There is no per-user/command authorization model and
  CLI execution has firmware-management privileges. Password comparison is not a
  documented constant-time authentication design. The existing native localhost
  fixture accepts test; it is synthetic and is not the production password.
- **Concurrency/lifecycle limits.** Two total TCP slots, one SSH owner/channel,
  bounded output, foreground scheduling-dependent deadlines and nominal30-second
  generic TCP idle eviction. Synchronous long commands can delay housekeeping.
- **Limited validation.** One physical SWTGW218AS unit; no certification for other
  board variants, adversarial deployment, long sessions or complete runtime stack
  coverage. This image does not include the separate SNMP integration.

Review/testing only: keep the PR draft. Passing these tests does not resolve
host identity, entropy, authentication isolation, rekeying or stack/IRQ safety.
