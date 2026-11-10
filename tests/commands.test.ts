import { describe, it, expect } from 'vitest';
import { isCommandAllowed } from '../src/policy.js';
import type { Grant } from '../src/types.js';

const grant: Grant = {
  tiers: ['client-work'],
  allow: ['*'],
  commands: ['npx prisma *', 'npm run deploy'],
};

describe('isCommandAllowed', () => {
  it('allows an exact match', () => {
    expect(isCommandAllowed(grant, 'npm', ['run', 'deploy'])).toBe(true);
  });

  it('allows a wildcard match', () => {
    expect(isCommandAllowed(grant, 'npx', ['prisma', 'migrate', 'deploy'])).toBe(true);
  });

  it('denies the classic env-printing escape', () => {
    expect(isCommandAllowed(grant, 'node', ['-e', 'console.log(process.env)'])).toBe(false);
  });

  it('denies a command not on the list', () => {
    expect(isCommandAllowed(grant, 'curl', ['https://evil.example'])).toBe(false);
  });

  it('denies when the command list is empty', () => {
    expect(isCommandAllowed({ ...grant, commands: [] }, 'npm', ['run', 'deploy'])).toBe(false);
  });

  it('treats shell metacharacters as literal arguments, not chaining', () => {
    expect(isCommandAllowed(grant, 'npm', ['run', 'deploy', '&&', 'curl', 'evil'])).toBe(false);
  });

  it('honours an explicit wildcard list', () => {
    expect(isCommandAllowed({ ...grant, commands: ['*'] }, 'anything', ['goes'])).toBe(true);
  });
});
