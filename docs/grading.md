# Grading and packaging

`pcapforge package` splits a run into what students get and what stays with the instructor:

```console
$ pcapforge package out/ot-modbus-write-manipulation_easy_42 --out handouts
handouts/ot-modbus-write-manipulation_easy_42-student.zip
handouts/ot-modbus-write-manipulation_easy_42-instructor.zip
```

- `<run>-student.zip`: the capture, `briefing.md` and `submission_template.yaml`, nothing else.
- `<run>-instructor.zip`: the whole run directory, including `answers.json`, `siem/` and `detections/`.

Without `--out` the zips are written next to the run directory. Several run directories can be packaged at
once (`pcapforge package out/*/ --out handouts`). The zips are byte-identical for the same run.

Students fill in `submission_template.yaml` (one file per student, named after the student), e.g.
`jane-doe.yaml` for the easy run above:

```yaml
# 1. Which IP address issued the unauthorized Modbus write requests?
#    (10 points; answer: an IP address)
source_ip: 10.241.35.219
# 2. Which MAC address did the sensor see on the frames carrying those write requests?
#    (5 points; answer: a MAC address)
source_mac: B8-27-EB-23-26-6D
target_ip: 10.241.35.159
first_write: 2025-03-22 11:45:36.4
points_changed: [pid_level_ti, level_high_alarm, level_low_alarm]
values_written: {pid_level_ti: 1587, level_high_alarm: 635, level_low_alarm: 0, chlorine_dose_sp: 8.45}
functions_used: [6, 16]
discovery: Rockwell Automation 2080-LC50-24QWB
impact: [chlorine_residual, level_high, level_low]
joined_host_name: raspberrypi
technique: T0831
```

A whole class can also hand in one CSV with the columns `student,question,answer`. Repeat a row to give
several elements of a list (`alice,points_changed,pid_level_ti`), or write them in one cell separated by
commas; map answers are `name=value` pairs (`pid_level_ti=1587; level_low_alarm=0`).

```console
$ pcapforge grade out/ot-modbus-write-manipulation_easy_42/answers.json submissions/jane-doe.yaml
jane-doe: 85/100 (85 %)   [submissions/jane-doe.yaml]
question          type       score     result   given
----------------  ---------  --------  -------  ----------------------------------------
source_ip         ip         10/10     correct  10.241.35.219
source_mac        mac        5/5       correct  B8-27-EB-23-26-6D
target_ip         ip         10/10     correct  10.241.35.159
first_write       timestamp  10/10     correct  2025-03-22 11:45:36.4
points_changed    set        11.25/15  partial  ["pid_level_ti", "level_high_alarm", "l…
values_written    map        11.25/15  partial  {"pid_level_ti": "1587", "level_high_al…
functions_used    set        2.5/5     partial  ["6", "16"]
discovery         text       10/10     correct  Rockwell Automation 2080-LC50-24QWB
impact            set        10/10     correct  ["chlorine_residual", "level_high", "le…
joined_host_name  text       5/5       correct  raspberrypi
technique         text       0/5       wrong    T0831

$ pcapforge grade answers.json submissions/*.yaml class.csv --json > grades.json
```

`first_write` is 0.38 s off but inside the key's `tolerance_s: 1`; `points_changed` names 3 of the 4 points
(3/4 × 15); `values_written` has 3 of 4 values within 0.5 % (8.45 is 1.1 % off 8.36); `functions_used` has
one correct and one extra code (1/2 × 5).

Each question is scored by its `type` in `answers.json`:

| type | correct when | partial credit |
|---|---|---|
| `ip` | same address; whitespace and leading zeros (`10.241.035.219`) ignored | - |
| `mac` | same 12 hex digits; case and `:` `-` `.` separators ignored | - |
| `number` | equal, or within `tolerance` when the key has one | - |
| `timestamp` | within `tolerance_s`; ISO 8601 with `T` or space, any fractional digits, `Z` or an offset; times without a zone are UTC | - |
| `set` | same elements, any order, case-insensitive | \|correct ∩ given\| / \|correct ∪ given\| × points: missing and extra elements both cost |
| `map` | every key present with the right value (numbers within 0.5 %) | matched keys / \|answer keys ∪ given keys\| × points |
| `text` | the answer or any `accept` alternative, ignoring case and repeated whitespace | - |

Blank answers score 0. Question ids that are not in the key are listed under the student and not scored.
With more than one student the report ends with a class summary (one column per question, numbered as
in `briefing.md`). `--json` prints every student's score, percentage, per-question result
(`correct`, `partial`, `wrong`, `blank`), given and expected answer. `grade` always exits 0 once the files
could be read.

## Hints, CTFd and the debrief report

- `pcapforge grade answers.json <submissions>` scores student answers. Hints listed under `hints_used` cost 20 % of the question's points (rounded up).
- `pcapforge export-ctfd <run dir>` writes one CTFd challenge per question in the `ctfcli` format (`ctfd/qNN-<id>/challenge.yml`). Install each with `ctf challenge install <dir>`. The first challenge carries the capture and the briefing. Sets, maps and timestamps use a canonical flag format that each challenge description states.
- `pcapforge report <run dir> [--grades grades.json]` writes `report.html` for the debrief: one self-contained page (inline SVG, no external resources) with the incident timeline and frame numbers, before/after charts of the changed setpoints and affected measurements (needs `siem/`, i.e. `--siem` or `pcapforge export`), the answers with their tshark checks, and optional class results from `pcapforge grade --json`.
