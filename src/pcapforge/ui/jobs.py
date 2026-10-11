"""Background jobs of the web UI. One worker thread runs them in submission order: recordings
share the loopback range and the recording cache, so two generations never run at once."""

from __future__ import annotations

import itertools
import queue
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

_RECORDING = re.compile(r"recording (\d+)/(\d+)")
LOG_LINES = 200


@dataclass
class Job:
    id: int
    kind: str                     # generate | verify | export | report | package | ctfd
    title: str
    run: str | None = None        # run directory name; a generate job learns it when it finishes
    state: str = "queued"         # queued | running | done | failed
    log: list[str] = field(default_factory=list)
    progress: float | None = None  # fraction of the recording, while it runs
    result: str | None = None     # one-line outcome
    error: str | None = None
    created: float = field(default_factory=time.time)
    finished: float | None = None

    def note(self, message: str) -> None:
        """A progress line; consecutive ``recording i/n`` lines replace each other."""
        match = _RECORDING.fullmatch(message)
        if match:
            done, total = int(match.group(1)), int(match.group(2))
            self.progress = done / total if total else None
            if self.log and _RECORDING.fullmatch(self.log[-1]):
                self.log[-1] = message
                return
        self.log.append(message)
        del self.log[:-LOG_LINES]

    def as_dict(self) -> dict:
        return {"id": self.id, "kind": self.kind, "title": self.title, "run": self.run, "state": self.state,
                "log": list(self.log), "progress": self.progress, "result": self.result, "error": self.error}


class Jobs:
    def __init__(self) -> None:
        self._jobs: dict[int, Job] = {}
        self._lock = threading.Lock()
        self._queue: queue.Queue[tuple[Job, Callable[[Job], str | None]]] = queue.Queue()
        self._ids = itertools.count(1)
        threading.Thread(target=self._work, name="pcapforge-ui-jobs", daemon=True).start()

    def submit(self, kind: str, title: str, work: Callable[[Job], str | None], run: str | None = None) -> Job:
        """Queue ``work(job)``; its return value becomes ``job.result``, an exception ``job.error``."""
        with self._lock:
            job = Job(next(self._ids), kind, title, run)
            self._jobs[job.id] = job
        self._queue.put((job, work))
        return job

    def get(self, job_id: int) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def all(self) -> list[Job]:
        """Newest first."""
        with self._lock:
            return sorted(self._jobs.values(), key=lambda j: -j.id)

    def active_for(self, run: str) -> list[Job]:
        return [j for j in self.all() if j.run == run and j.state in ("queued", "running")]

    def _work(self) -> None:
        while True:
            job, work = self._queue.get()
            job.state = "running"
            try:
                job.result = work(job)
                job.state = "done"
            except Exception as exc:  # noqa: BLE001 - a failed job is shown, the worker keeps going
                job.error = f"{type(exc).__name__}: {exc}"
                job.state = "failed"
            finally:
                job.progress = None
                job.finished = time.time()
