# Third-party notices

The Windows placement distribution (`nix build .#placement-artifact`) redistributes two unmodified third-party binaries. Each is fetched at a pinned hash from its official release and ships with the license text below, in the distribution's `LICENSES/` and in this repository's `LICENSES/`.

| Binary | Version | License | Official release asset | Source code |
|---|---|---|---|---|
| `sops.exe` | SOPS 3.13.2 | MPL-2.0, [`LICENSES/sops-v3.13.2.txt`](LICENSES/sops-v3.13.2.txt) | https://github.com/getsops/sops/releases/download/v3.13.2/sops-v3.13.2.amd64.exe | https://github.com/getsops/sops/tree/v3.13.2 |
| `age-keygen.exe` | age 1.3.2 | BSD-3-Clause, [`LICENSES/age-v1.3.2.txt`](LICENSES/age-v1.3.2.txt) | `age/age-keygen.exe` of https://github.com/FiloSottile/age/releases/download/v1.3.2/age-v1.3.2-windows-amd64.zip | https://github.com/FiloSottile/age/tree/v1.3.2 |

`LICENSES/age-v1.3.2.txt` is the exact `age/LICENSE` shipped in that release archive (the age and Go notices); `LICENSES/sops-v3.13.2.txt` is the exact `LICENSE` of SOPS v3.13.2. Both are compared with their upstream copies when the distribution is built. They are reproduced as published; this file does not claim that they cover every module compiled into those binaries.

This notice covers only those two binaries in the placement distribution. Other artifacts, including the effect artifact's Nix closure, are not assessed here. GitHub Actions may obtain other external tools at exact pinned identities during a run, including the nixpkgs packages locked by `flake.lock`; those remain governed by their upstream licenses. This file and `LICENSES/` must be updated before any further third-party material is redistributed from this repository.
