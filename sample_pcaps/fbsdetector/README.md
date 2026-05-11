# FBSDetector NAS traces (vendored)

Third-party LTE NAS captures with per-packet attack/benign ground-truth labels.
Used by this project as an **objective** evaluation set: the detector is judged
against labels written by the dataset authors, not by us.

## Provenance

- Upstream: https://github.com/SysNetS/fbsdetector
- Commit: `8b7d8ddb9de7fc31e12f0340749dc7b5d9d95f98` (2025-08-28)
- Paper: Mubasshir, Karim, Bertino, "Gotta Detect 'Em All: Fake Base Station and
  Multi-Step Attack Detection in Cellular Networks", arXiv:2401.04958
- License: CC0 1.0 Universal (see `LICENSE.upstream`)

## What is here

Nine NAS pcaps and their corresponding per-packet label files, copied verbatim
from `example_traces/nas/` and `example_trace_labels/nas/` upstream:

```
exp{1..9}_nas.pcap        - NAS PDUs, one per packet
exp{1..9}_nas_label.txt   - Python list of 0/1, one element per packet
```

Each `exp{N}_nas_label.txt` is a Python literal of the form
`nas_label = [0, 0, 1, 1, 0, ...]`. The list length equals the pcap packet
count exactly (verified for all nine files). `0` marks a benign packet, `1`
marks a packet that is part of an attack window.

The labels are binary (benign vs. attack). The upstream README defines a
22-class attack taxonomy for the CSV datasets under `dataset/`, but the pcap
label files do **not** carry the per-class attack ID, so the specific attack
behind each `1`-run in a given pcap is not declared by upstream.

## How this project uses these files

Of the 22 attacks in the upstream taxonomy, this project's three detection
rules target a subset:

- IMSI catching (label 15) - matched against rule
  *IMSI requested in cleartext when a valid GUTI was available*.
- Bidding down with AttachReject (label 5) and Bidding down with TAUReject
  (label 21) - matched against rule
  *TAU/Attach reject with abnormal cause codes that force IMSI re-disclosure*.
- Authentication relay attack (label 9) - relevant to rule *AKA skipped or
  failed*.

The detector consumes the pcap; the label file is consumed only by the
evaluation harness, which compares the detector's per-packet verdict against
the upstream ground truth.

## Citation

```
@misc{mubasshir2025gottadetectemall,
      title={Gotta Detect 'Em All: Fake Base Station and Multi-Step Attack Detection in Cellular Networks},
      author={Kazi Samin Mubasshir and Imtiaz Karim and Elisa Bertino},
      year={2025},
      eprint={2401.04958},
      archivePrefix={arXiv},
      primaryClass={cs.CR},
      url={https://arxiv.org/abs/2401.04958}
}
```
