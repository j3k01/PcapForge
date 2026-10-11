# Web UI

`pcapforge ui` serves a small local web interface on `http://127.0.0.1:8765/` and opens it in the browser.
It works on the same output directory as `generate` (`--out`, default `out`):

- **scenarios**: the catalog; per scenario its summary, ATT&CK techniques, questions and a level matrix
  (every knob per level, values that change from the level before highlighted), plus a generate form
  (level, seed, length, language, format, SIEM / Zeek export). Its "batch" section takes a seed list (one
  per line, e.g. student logins; `#` comments and blanks skipped, at most 200, duplicates refused) and an
  optional base seed that works like `--base-seed`; each seed becomes its own job.
- **jobs**: generation and the run actions run one at a time in the background; the job list and the job
  page update live with the recording progress and the log, then link the run.
- **runs**: filterable by scenario and level, grouped with a "package all" button per group. Per run the
  capture metadata, a network map (subnets, hosts, routers, the SPAN segment, IPv6 hosts), the host table,
  a traffic overview (a per-protocol strip chart over the capture time with the answer-key events marked,
  built by the `traffic` action from the capture and cached in `traffic.json`; the top conversations from
  `siem/flows.jsonl`), the timeline, the answer key behind a "reveal answers" toggle, the files (download),
  the students' submissions with the class results, and buttons for verify, SIEM / Zeek export, traffic,
  grade, the debrief report (with the class results once graded), the student / instructor zips and the
  CTFd export. Each section heading has its downloads: `hosts.csv`, `traffic.csv` (packets per protocol and
  time bucket, once scanned), `flows.csv` (every flow, not only the top ones) and `flows.jsonl`,
  `timeline.csv`, `answer-key.csv` (questions, answers, hints, tshark filters) and `answers.json`,
  `submissions.zip`, `grades.csv` and `grades.json`, the capture, and the whole run as one zip; every
  directory (`siem/`, `zeek/`, ...) downloads as a zip too. CSV files are UTF-8 with a byte order mark.

`pcapforge ui --student [--show-score]` is the student side on the same output directory, and nothing else:
students sign in, see their exercises (runs whose seed is their login, otherwise all runs), download the
capture, `briefing.md` and `submission_template.yaml`, read the briefing and answer the questions in a form
(hints with their cost, as in the template). The pages follow the exercise's language (en, pl, de). A
submission is saved as `<run>/submissions/<login>.yaml` in the format `pcapforge grade` reads; resubmitting
overwrites it. With `--show-score` students see their score per question right away, never the expected
answers. The instructor's `grade` action writes `<run>/grades.json` (same as `pcapforge grade --json`).

Access: on the instructor's **students** page, paste the class list (`login` or `login, Display Name` per
line; the same logins can be the seed list of a batch). Each new student gets a random access code, shown
once on a printable page; `<out>/roster.json` keeps only salted PBKDF2 hashes, and codes can be reset or
students removed. With a roster, students sign in with login + code and get a signed 12-hour session
(secret in `<out>/.ui-secret`); each student sees and overwrites only their own submission. Without a
roster the student side is honour-system: any name is accepted.

Standard library only, no extra dependency. It listens on 127.0.0.1 and refuses other `Host` headers and
cross-origin form posts. `--host 0.0.0.0` makes it reachable from the network over plain HTTP: in
instructor mode anyone who reaches it can start jobs and read the answer keys, so expose only the student
mode to a class network, preferably with a roster.
