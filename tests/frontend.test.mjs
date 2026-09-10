import test from 'node:test';
import assert from 'node:assert/strict';
import { AnalysisWatcher } from '../src/quanta/web/static/progress.mjs';
import { normalizeRepositoryUrl } from '../src/quanta/web/static/repository.mjs';

test('repository input accepts PyJWT links and shorthand as the same HTTPS URL', () => {
  for (const input of [
    'https://github.com/jpadilla/pyjwt',
    'https://github.com/jpadilla/pyjwt/',
    'https://github.com/jpadilla/pyjwt.git',
    'https://www.github.com/jpadilla/pyjwt',
    'http://github.com/jpadilla/pyjwt',
    'HTTPS://GITHUB.COM/jpadilla/pyjwt',
    'github.com/jpadilla/pyjwt',
    'www.github.com/jpadilla/pyjwt.git/',
    'jpadilla/pyjwt',
    '  jpadilla/pyjwt  ',
  ]) {
    assert.equal(normalizeRepositoryUrl(input), 'https://github.com/jpadilla/pyjwt', input);
  }
  assert.equal(normalizeRepositoryUrl('moayadbah/Quanta'), 'https://github.com/moayadbah/Quanta');
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
