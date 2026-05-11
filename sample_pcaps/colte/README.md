# CoLTE legit-attach pcap (fetch by reference)

Independent legitimate-attach capture, used as a false-positive baseline
alongside the benign segments inside the FBSDetector pcaps.

## Why fetched, not vendored

The CoLTE software is MIT-licensed, but the PCAP library on the CoLTE blog
does not carry an explicit license for the captures themselves. To stay clear
of the redistribution question, we don't mirror the pcap into this repo. The
demo runner fetches it from the original source on first run, verifies the
SHA-256, and extracts the single file we use.

## What gets fetched

- Source: https://blog.colte.network/pcap-library/
- ZIP URL: https://blog.colte.network/wp-content/uploads/2020/03/pcaps.zip
- File extracted: `pcaps/2_firstattach.pcap` (described upstream as
  "Successful Initial Attach")
- ZIP SHA-256: `369c3b3910f166851063e3b95e973c537568567b928a0774df180a847c1c323f`
- PCAP SHA-256: `925d6927d8db45c46112443b1371d6998c2540cc8d54a65a09a75a591b5d647f`

## How

```
./sample_pcaps/colte/fetch.sh
```

The script is idempotent: if `2_firstattach.pcap` is already present and its
hash matches, it exits without re-downloading. The pcap itself is gitignored.

## Note

PCAP 2 contains a Sync Failure on the first authentication attempt
(documented by CoLTE as normal first-attach behavior when the network has no
valid SQN for the SIM). The detection rules treat the post-resync attach as
the legitimate flow.
