# OpenVG — Fork Provenance

**OpenVG** is a community-maintained, **MIT-licensed** fork of
[Vulnogram](https://github.com/Vulnogram/Vulnogram).

## Why this fork exists

Vulnogram was released under the MIT License from 2017 onward. On
2026-01-21 the upstream project [relicensed away from MIT][relicense]
(commit `ae0713c`, *"Update the license to prevent phishing and abuse"*),
replacing `LICENSE.txt` with a new, more restrictive `LICENSE.md`.

OpenVG continues the project from the **last commit that was still under
the MIT License**, so the code and all of its history remain free and
open-source under MIT.

## Exact fork point

| | |
|---|---|
| Upstream | https://github.com/Vulnogram/Vulnogram |
| Fork commit | `41702c4c6f7ca218612662aba56c3da1978c3699` |
| Commit subject | `remove dead code` |
| Commit date | 2026-01-21 |
| Upstream version at fork | `0.6.0` |
| License at fork | MIT (`LICENSE.txt`, © 2017-2019 Chandan B. N.) |

The relicensing commit `ae0713c` lands roughly two minutes after the fork
point on the same day; OpenVG deliberately branches from the commit
immediately **before** it.

## What this fork preserves and drops

- **Preserved:** the full MIT-era git history — all 505 commits that are
  ancestors of the fork point, every one authored while the project was
  MIT-licensed, including the original release tags (`v0.0.5`, `v0.0.6`,
  `v0.0.9`, `v0.1.0-rc1`).
- **Preserved:** the original `LICENSE.txt` and copyright notice, retained
  in full as required by the MIT License.
- **Dropped:** the 102 upstream commits made after the fork point (which
  include the relicensing), the post-fork release tag `v1.0.0-beta1`, and
  the `origin` remote pointing at upstream. None of the post-MIT objects
  remain reachable in this repository.

## Attribution

This project is derived from Vulnogram, created by Chandan B. N. and the
Vulnogram contributors. Their copyright notice is preserved in
[`LICENSE.txt`](./LICENSE.txt). OpenVG is an independent community fork and
is **not affiliated with or endorsed by** the upstream Vulnogram project.

[relicense]: https://github.com/Vulnogram/Vulnogram/commit/ae0713c627dbb4a88031ee428d8d288854425079
