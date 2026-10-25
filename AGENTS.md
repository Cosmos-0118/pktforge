# pktforge: instructions for AI agents

Task: *turn a lab description into a working Cisco Packet Tracer file.* Use this tool; do not hand-write Packet
Tracer XML (it is ~1 MB, strict, and fails silently).

```bash
pktforge guide            # full usage guide
pktforge guide lessons    # why files "look right but pass no traffic" (read before debugging)
pktforge schema           # JSON Schema for the spec
pktforge init lab         # starter spec -> lab.json
pktforge check lab.json --json
pktforge build lab.json -o out
```

Install if missing (needs Python 3.10+, nothing else):

```bash
curl -fsSL https://raw.githubusercontent.com/Cosmos-0118/pktforge/main/install.sh | sh
```

```powershell
irm https://raw.githubusercontent.com/Cosmos-0118/pktforge/main/install.ps1 | iex
```

From a checkout without installing: `python -m pktforge <command>`.

## Rules

1. Loop `check --json` until `ok` is true; each finding carries a `fix`. Do not pass `--force` to silence errors.
2. Put IP addresses in the router `config`, never in port fields. Use `/nn` on end-device `ip`.
3. Use verified models (`2911`, `2960-24TT`, `PC-PT`, `Server-PT`) unless the user needs something else; say so
   when you use an unverified one.
4. `build` output is a `.pkt`. Give the user that file; no conversion step is needed.
5. Report what you did not verify. `check` + `build` prove consistency, **not** that traffic flows. If you can
   open Packet Tracer, do, and read `show ip interface brief` first.
6. List the manual steps `build` prints (console cables etc.) in your answer.

## Working on pktforge itself

* `python -m unittest discover -s tests` (stdlib only, ~2 s). Run it after every change.
* `pktforge/_vendor/` is vendored GPL code (codec + `lab_api`); change it only to fix a real bug and note why.
* A new lint rule needs a test in `tests/test_pktforge.py` and a line in `pktforge/data/LESSONS.md`.
* A new device model is "verified" only after it was opened in Packet Tracer and passed traffic: add it to
  `VERIFIED_MODELS` in `pktforge/ports.py` then, not before.
* `pktforge/data/GUIDE.md` is the canonical usage text; keep it and the README in step.
