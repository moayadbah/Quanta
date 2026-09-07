import test from 'node:test';
import assert from 'node:assert/strict';
import { AnalysisWatcher } from '../src/quanta/web/static/progress.mjs';

function fixture(responses) {
  const callbacks = [];
  const timers = new Map();
  const sources = [];
  let next = 0;
  class Source {
    constructor() { this.handlers = {}; sources.push(this); }
    addEventListener(event, handler) { this.handlers[event] = handler; }
    emit(event, data) { this.handlers[event](data === undefined ? {} : { data: JSON.stringify(data) }); }
    close() { this.closed = true; }
  }
  const watcher = new AnalysisWatcher('job', {
    done: () => callbacks.push('done'),
    failure: (data) => callbacks.push(data.error_code),
    progress: (pct) => callbacks.push(pct),
  }, {
    EventSource: Source,
    fetch: async () => {
      const item = responses.shift();
      if (item instanceof Error) throw item;
      return { ok: true, status: 200, json: async () => item };
    },
    setTimeout: (fn, ms) => { assert.equal(ms, 3000); timers.set(++next, fn); return next; },
    clearTimeout: (id) => timers.delete(id),
  }).start();
  return { watcher, callbacks, timers, sources, tick: async () => {
    const [key, fn] = timers.entries().next().value;
    timers.delete(key);
    await fn();
  }};
}

test('transport loss recovers across API restart and reaches completed report', async () => {
  const f = fixture([new Error('API restarting'), { status: 'running', progress: 44 },
    { steps: [] }, { status: 'succeeded' }]);
  f.sources[0].emit('error');
  assert.equal(f.sources[0].closed, true);
  await f.tick();
  await f.tick();
  assert.deepEqual(f.callbacks, [44]);
  await f.tick();
  assert.deepEqual(f.callbacks, [44, 'done']);
  assert.equal(f.timers.size, 0);
});

test('server error is terminal, not a transport retry', () => {
  const f = fixture([]);
  f.sources[0].emit('error', { error_code: 'ANALYSIS_TIMEOUT' });
  assert.deepEqual(f.callbacks, ['ANALYSIS_TIMEOUT']);
  assert.equal(f.timers.size, 0);
});

test('stopping a view cancels retries and ignores old stream events', () => {
  const f = fixture([]);
  f.sources[0].emit('error');
  f.watcher.stop();
  f.sources[0].emit('done', {});
  assert.equal(f.timers.size, 0);
  assert.deepEqual(f.callbacks, []);
});

test('artifact fetch failure can recover through polling', async () => {
  const f = fixture([{ status: 'succeeded' }]);
  let attempts = 0;
  f.watcher.callbacks.done = async () => { if (++attempts === 1) throw new Error('restart'); };
  await f.watcher.finish();
  await f.tick();
  assert.equal(attempts, 2);
  assert.equal(f.watcher.stopped, true);
});

test('the app entrypoint is served as a module so its progress import can load', async () => {
  const { readFile } = await import('node:fs/promises');
  const html = await readFile(new URL('../src/quanta/web/static/guide.html', import.meta.url), 'utf8');
  assert.match(html, /<script src="\/app\.js" type="module"><\/script>/);
});
