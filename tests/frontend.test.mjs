import test from 'node:test';
import assert from 'node:assert/strict';
import { AnalysisWatcher } from '../src/quanta/web/static/progress.mjs';
import { normalizeRepositoryUrl } from '../src/quanta/web/static/repository.mjs';
import { requestJson } from '../src/quanta/web/static/request.mjs';
import { watchSavedScan } from '../src/quanta/web/static/saved-scan.mjs';

function savedScan(overrides = {}) {
  const states = [], retries = [], timers = [];
  const options = {
    isCurrent: () => true,
    getStatus: async () => { throw new Error('unexpected status request'); },
    loadResult: async () => {},
    progress: (data) => states.push(data.status),
    failure: (data) => assert.fail(data.detail || data.status),
    queued: () => assert.fail('a completed scan must never run again'),
    retry: (error) => retries.push(error),
    schedule: (fn, delay) => { assert.equal(delay, 3000); timers.push(fn); },
    ...overrides,
  };
  return { options, states, retries, timers };
}

test('opening a completed history item loads its report directly without showing queued', async () => {
  let loaded = 0;
  const f = savedScan({ initial: { status: 'succeeded' }, loadResult: async () => { loaded++; } });
  await watchSavedScan(f.options);
  assert.equal(loaded, 1);
  assert.ok(f.states.every((state) => state === 'loading_report'));
  assert.equal(f.timers.length, 0);
});

test('interrupted report downloads retry without re-queuing or restarting the completed scan', async () => {
  let attempts = 0;
  const f = savedScan({ initial: { status: 'succeeded' }, loadResult: async () => {
    if (++attempts === 1) throw new Error('mobile connection interrupted');
  }});
  await watchSavedScan(f.options);
  assert.equal(f.retries.length, 1);
  await f.timers.shift()();
  assert.equal(attempts, 2);
  assert.ok(f.states.every((state) => state === 'loading_report'));
  assert.equal(f.timers.length, 0);
});

test('unknown scans are checked before showing a queue, then finish from real status', async () => {
  let queued = 0, loaded = 0;
  const statuses = [{ status: 'queued' }, { status: 'succeeded' }];
  const f = savedScan({
    getStatus: async () => statuses.shift(),
    queued: () => { queued++; },
    loadResult: async () => { loaded++; },
  });
  await watchSavedScan(f.options);
  assert.deepEqual(f.states, ['checking', 'queued']);
  await f.timers.shift()();
  assert.equal(queued, 1);
  assert.equal(loaded, 1);
  assert.equal(f.states.at(-1), 'loading_report');
  assert.equal(f.timers.length, 0);
});

test('leaving a scan prevents a late status response from replacing the new view', async () => {
  let current = true, resolve;
  const f = savedScan({
    isCurrent: () => current,
    getStatus: () => new Promise((done) => { resolve = done; }),
    loadResult: () => assert.fail('stale view loaded'),
  });
  const pending = watchSavedScan(f.options);
  current = false;
  resolve({ status: 'succeeded' });
  await pending;
  assert.deepEqual(f.states, ['checking']);
  assert.equal(f.timers.length, 0);
});

for (const stalled of ['headers', 'body']) {
  test(`a stalled ${stalled} read times out so scan polling can recover`, async () => {
    let expire, signal, cancelled = false;
    const pending = requestJson('/status', {}, 30000, {
      fetch: async (_path, options) => {
        signal = options.signal;
        if (stalled === 'headers') return new Promise(() => {});
        return { json: () => new Promise(() => {}) };
      },
      setTimeout: (fn, delay) => { assert.equal(delay, 30000); expire = fn; return 1; },
      clearTimeout: (id) => { assert.equal(id, 1); cancelled = true; },
    });
    const rejected = assert.rejects(pending, /timed out/);
    expire();
    await rejected;
    assert.equal(signal.aborted, true);
    assert.equal(cancelled, true);
  });
}

test('the read deadline does not interrupt a long-running scan POST', async () => {
  const result = await requestJson('/run', { method: 'POST' }, 0, {
    fetch: async () => ({ ok: true, json: async () => ({ status: 'succeeded' }) }),
    setTimeout: () => assert.fail('write must not use the read deadline'),
  });
  assert.equal(result.data.status, 'succeeded');
});

test('repository input accepts PyJWT links and shorthand as the same HTTPS URL', () => {
  for (const input of [
    'https://github.com/jpadilla/pyjwt',
    'https://github.com/jpadilla/pyjwt/',
    'https://www.github.com/jpadilla/pyjwt',
    'http://github.com/jpadilla/pyjwt',
    'HTTPS://GITHUB.COM/jpadilla/pyjwt',
    'github.com/jpadilla/pyjwt',
    'jpadilla/pyjwt',
    '  jpadilla/pyjwt  ',
  ]) {
    assert.equal(normalizeRepositoryUrl(input), 'https://github.com/jpadilla/pyjwt', input);
  }
  assert.equal(normalizeRepositoryUrl('moayadbah/Quanta'), 'https://github.com/moayadbah/Quanta');
  assert.equal(normalizeRepositoryUrl('www.github.com/jpadilla/pyjwt.git/'), 'https://github.com/jpadilla/pyjwt.git');
  assert.equal(normalizeRepositoryUrl('owner/repo.git.git'), 'https://github.com/owner/repo.git.git');
});

test('repository input rejects ambiguous names and unsafe URL shapes', () => {
  for (const input of [
    '', 'pyjwt', null,
    'https://evil.com/jpadilla/pyjwt',
    'https://github.com.evil.com/jpadilla/pyjwt',
    'https://github.com@evil.com/jpadilla/pyjwt',
    'https://user:password@github.com/jpadilla/pyjwt',
    'https://github.com:443/jpadilla/pyjwt',
    '//github.com/jpadilla/pyjwt',
    'git@github.com:jpadilla/pyjwt.git',
    'https://github.com/jpadilla/pyjwt/tree/master',
    'https://github.com/jpadilla/pyjwt?tab=readme-ov-file',
    'https://github.com/jpadilla/pyjwt#readme',
    'https://github.com/jpadilla//pyjwt',
    'https://github.com/jpadilla/pyjwt//',
    'https://github.com/jpadilla/%2e%2e',
    'https://github.com/../pyjwt',
    'jpadilla/..', 'jpadilla/.git',
    'jpadilla/py\njwt', 'jpadilla/py\u200bjwt',
    'jpadilla/' + 'a'.repeat(101),
    'a'.repeat(101) + '/pyjwt',
  ]) {
    assert.equal(normalizeRepositoryUrl(input), null, String(input));
  }
});

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
