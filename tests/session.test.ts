import { describe, it, expect } from 'vitest';
import { SessionState } from '../src/session.js';

const T0 = 1_000_000;
const MIN = 60_000;

describe('SessionState', () => {
  it('generates a broker id', () => {
    expect(new SessionState({ idleMinutes: 30 }).brokerId).toMatch(/^[0-9a-f]{16}$/);
  });

  it('binds to the first workspace it sees', () => {
    const s = new SessionState({ idleMinutes: 30 });
    expect(s.bindWorkspace('c:/work/globex')).toBe(true);
    expect(s.workspace).toBe('c:/work/globex');
  });

  it('accepts the same workspace again', () => {
    const s = new SessionState({ idleMinutes: 30 });
    s.bindWorkspace('c:/work/globex');
    expect(s.bindWorkspace('c:/work/globex')).toBe(true);
  });

  it('refuses to rebind to a different workspace', () => {
    const s = new SessionState({ idleMinutes: 30 });
    s.bindWorkspace('c:/work/globex');
    expect(s.bindWorkspace('c:/work/production')).toBe(false);
  });

  it('reports idle after the idle window with no activity', () => {
    const s = new SessionState({ idleMinutes: 30 });
    s.touch(T0);
    expect(s.isIdle(T0 + 29 * MIN)).toBe(false);
    expect(s.isIdle(T0 + 31 * MIN)).toBe(true);
  });

  it('is never idle while a run is in flight, and the clock restarts when it finishes', () => {
    const s = new SessionState({ idleMinutes: 30 });
    s.touch(T0);
    s.runStarted();
    expect(s.isIdle(T0 + 31 * MIN)).toBe(false);
    s.runFinished(T0 + 40 * MIN);
    expect(s.isIdle(T0 + 41 * MIN)).toBe(false);
    expect(s.isIdle(T0 + 71 * MIN)).toBe(true);
  });
});
