// pcapforge ui: the header's digital rain and live job pages. No dependencies.
"use strict";

(function rain() {
  const canvas = document.getElementById("rain");
  if (!canvas || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  const ctx = canvas.getContext("2d");
  const glyphs = "0123456789abcdef:.";
  const size = 12;
  let drops = [];
  function resize() {
    canvas.width = canvas.clientWidth;
    canvas.height = canvas.clientHeight;
    drops = Array.from({ length: Math.ceil(canvas.width / size) }, () => Math.random() * -20);
    ctx.font = `${size}px Consolas, monospace`;
  }
  function frame() {
    ctx.fillStyle = "rgba(3, 8, 5, 0.22)";
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    for (let i = 0; i < drops.length; i++) {
      const y = drops[i] * size;
      if (y > 0) {
        ctx.fillStyle = Math.random() < 0.05 ? "#c8ffd4" : "#25b84d";
        ctx.fillText(glyphs[(Math.random() * glyphs.length) | 0], i * size, y);
      }
      drops[i] = y > canvas.height && Math.random() > 0.96 ? Math.random() * -10 : drops[i] + 0.5;
    }
  }
  resize();
  window.addEventListener("resize", resize);
  setInterval(() => { if (!document.hidden) frame(); }, 70);
})();

(function jobPage() {
  const box = document.getElementById("job");
  if (!box) return;
  const id = box.dataset.id;
  const state = document.getElementById("job-state");
  const bar = document.getElementById("job-bar");
  const run = document.getElementById("job-run");
  const result = document.getElementById("job-result");
  const log = document.getElementById("job-log");
  async function poll() {
    let job;
    try {
      const response = await fetch(`/api/jobs/${id}`, { cache: "no-store" });
      if (!response.ok) return;
      job = await response.json();
    } catch (_) {
      setTimeout(poll, 3000);
      return;
    }
    state.textContent = job.state;
    state.className = `state-${job.state}`;
    bar.textContent = job.bar;
    result.textContent = job.result || job.error || "";
    if (job.run && !run.querySelector("a")) {
      const a = document.createElement("a");
      a.href = `/runs/${encodeURIComponent(job.run)}`;
      a.textContent = job.run;
      run.replaceChildren(a);
    }
    const atEnd = log.scrollTop + log.clientHeight >= log.scrollHeight - 4;
    log.textContent = job.log.join("\n");
    if (atEnd) log.scrollTop = log.scrollHeight;
    if (job.state === "queued" || job.state === "running") setTimeout(poll, 1000);
  }
  if (box.dataset.state === "queued" || box.dataset.state === "running") poll();
})();
