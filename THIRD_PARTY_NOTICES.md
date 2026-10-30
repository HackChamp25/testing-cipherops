# Third-party notices

CipherOps is released under the [MIT licence](LICENSE). It builds on, and links against, third-party software that
keeps its own licence. This file lists what, where it comes from and what you must do if you redistribute it. It is not
legal advice.

CipherOps is an independent project. It is **not affiliated with, sponsored by or endorsed by Verisign, Inc.**, NIST,
the IETF, the Open Quantum Safe project, NLnet Labs or the OpenSSL Project. Their names are used only to say which
software was measured.

## What is and is not in this repository

This repository contains **no third-party source code or binaries**. The Dockerfiles download OpenSSL, liboqs, the
Verisign MTL library and the Verisign MTL-mode ldns, NSD and Unbound forks from their public repositories at the exact
tags and commits pinned in [`ecosystem/stacks/`](ecosystem/stacks), and build them on your machine. The Docker images
you build are therefore **your** copy of that software.

If you **publish or distribute** a built image (or any binary from it), you take on the redistribution conditions below,
and you must ship the licence texts with it.

## Components

| Component | Used for | Licence | Source |
| --- | --- | --- | --- |
| Verisign MTL reference library | MTL signing and verification (`slh-dsa-mtl`) | The Clear BSD License, with a patent notice (see below) | <https://github.com/verisign/MTL> |
| Verisign MTL-mode ldns, NSD, Unbound | signer, authoritative server and validating resolver in the simulated lab | Derived from NLnet Labs' ldns, NSD and Unbound (BSD-3-Clause upstream); check the licence files in the pinned commit | <https://github.com/verisign> (`mtl-mode-ldns`, `mtl-mode-nsd`, `mtl-mode-unbound`) |
| liboqs | SLH-DSA (`slh-dsa`) and the primitive under MTL | MIT, with differently licensed third-party modules in subfolders | <https://github.com/open-quantum-safe/liboqs> |
| OpenSSL | classical algorithms (`ed25519`, `ecdsa-p256`, `rsa-2048`), TLS | Apache-2.0 | <https://github.com/openssl/openssl> |
| Fedora 42 (base image) | runtime and build tools | per package | <https://fedoraproject.org> |
| Python packages (`requirements*.txt`) | harness, statistics, dashboard | each package's own licence (permissive: BSD, MIT, Apache-2.0, ISC) | <https://pypi.org> |

Licences of the **pinned** ldns, NSD and Unbound commits have not been audited file by file here. Check them before
you redistribute anything, from the commits in the stack profile:

```bash
. ecosystem/stacks/draft06.env      # or latest.env
git clone https://github.com/verisign/mtl-mode-unbound.git /tmp/unbound
git -C /tmp/unbound checkout "$UNBOUND_COMMIT" && ls /tmp/unbound | grep -i -E 'licen|copying|notice'
```

Repeat for `mtl-mode-nsd` (`NSD_COMMIT`), `mtl-mode-ldns` (`LDNS_COMMIT`) and `MTL` (`MTL_COMMIT`).

## Verisign MTL: conditions to keep

The Verisign MTL repository ([`LICENSE.md`](https://github.com/verisign/MTL/blob/main/LICENSE.md)) combines a software
licence with a patent notice. If you redistribute MTL source or binaries:

- **Clear BSD License.** Keep the copyright notice (Copyright (c) 2026, VeriSign, Inc.), the licence conditions and the
  disclaimer in source and in the documentation shipped with binaries. Do not use Verisign's name or its contributors'
  names to endorse or promote a derived product without written permission.
- **No patent licence from the software licence.** The Clear BSD License expressly grants no patent rights.
- **Patent notice.** Verisign states that its public, royalty-free patent licences relate to MTL mode in furtherance of
  IETF standardisation, and that they are subject to the conditions in its IETF IPR declarations (see
  <https://datatracker.ietf.org/ipr/7388/> to `7392/` and <https://www.verisign.com/Declarations>). The notice to
  reproduce is:

  > This product is licensed under patents and/or patent applications owned by VeriSign, Inc. in furtherance of IETF
  > standardization which helps support the security, stability and resiliency of the Domain Name System (DNS) and the
  > internet. For more information about the patents, visit www.verisign.com/Declarations.

  Read the current declarations before you build a product on MTL; they, not this file, define what is licensed.

CipherOps only **measures** MTL; it does not modify or relink the library beyond compiling it with `-O2` (upstream
forces `-O0`) and calling it from `harness/mtlbench.c`.

## Standards and drafts

- FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA) are NIST publications, cited by name and number only.
- The MTL drafts (`draft-harvey-cfrg-mtl-mode`, `draft-fregly-dnsop-slh-dsa-mtl-dnssec`,
  `draft-kaizer-dnsop-ml-dsa-mtl-dnssec`, `draft-sheth-pqc-dnssec-strategy`) are IETF Internet-Drafts, © IETF Trust and
  their authors. This repository cites their titles, versions and abstract-level facts and does not reproduce them.
- [`ecosystem/drafts/`](ecosystem/drafts/README.md) holds the team's own working text for an Informational draft. It is
  not an IETF document.
