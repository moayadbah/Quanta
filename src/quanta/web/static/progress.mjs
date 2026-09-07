/** SSE progress with polling recovery. Transport injection keeps failure paths testable. */
export class AnalysisWatcher {
  constructor(jobId, callbacks, transport = {}) {
    this.jobId = jobId;
    this.callbacks = callbacks;
    this.fetch = transport.fetch || fetch;
    this.EventSource = transport.EventSource || EventSource;
    this.schedule = transport.setTimeout || setTimeout;
    this.unschedule = transport.clearTimeout || clearTimeout;
    this.source = null;
    this.timer = null;
    this.stopped = false;
    this.finishing = false;
  }

  start() {
    const source = new this.EventSource(`/api/v1/analyses/${this.jobId}/events`);
    this.source = source;
    const receive = (event, callback) => source.addEventListener(event, (message) => {
      if (this.stopped || this.finishing || this.source !== source) return;
      try { callback(JSON.parse(message.data)); }
      catch { this.poll(); }
    });
    receive("plan", (data) => this.callbacks.plan?.(data));
    receive("step", (data) => this.callbacks.step?.(data));
    receive("status", (data) => this.callbacks.status?.(data));
    receive("progress", (data) => this.callbacks.progress?.(data.pct));
    receive("done", () => this.finish());
    receive("failed", (data) => this.fail(data));
    source.addEventListener("error", (message) => {
      if (this.stopped || this.finishing || this.source !== source) return;
      if (typeof message.data === "string") {
        try { this.fail(JSON.parse(message.data)); }
        catch { this.poll(); }
      } else this.poll();
    });
    return this;
  }

  disconnect() {
    this.source?.close();
    this.source = null;
    if (this.timer !== null) this.unschedule(this.timer);
    this.timer = null;
  }

  stop() {
    this.stopped = true;
    this.disconnect();
  }

  fail(data) {
    if (this.stopped) return;
    this.stop();
    this.callbacks.failure?.(data);
  }

  async finish() {
    if (this.stopped || this.finishing) return;
    this.finishing = true;
    this.disconnect();
    try {
      await this.callbacks.done?.();
      this.stop();
    } catch {
      this.finishing = false;
      this.poll();
    }
  }

  poll() {
    if (this.stopped || this.finishing || this.timer !== null) return;
    this.disconnect();
    this.callbacks.polling?.();
    this.timer = this.schedule(async () => {
      this.timer = null;
      if (this.stopped) return;
      try {
        const response = await this.fetch(`/api/v1/analyses/${this.jobId}`);
        const status = await response.json();
        if (this.stopped) return;
        if (response.status === 404) { this.fail(status); return; }
        if (!response.ok) throw new Error("status unavailable");
        if (status.status === "succeeded") { await this.finish(); return; }
        if (["failed", "timeout"].includes(status.status)) { this.fail(status); return; }
        this.callbacks.status?.(status);
        const traceResponse = await this.fetch(`/api/v1/analyses/${this.jobId}/trace`);
        if (traceResponse.ok) {
          const trace = await traceResponse.json();
          if (this.stopped) return;
          for (const step of trace.steps) this.callbacks.step?.(step);
        }
        if (this.stopped) return;
        this.callbacks.progress?.(status.progress);
      } catch { /* API restarts and interrupted requests are recoverable. */ }
      this.poll();
    }, 3000);
  }
}
