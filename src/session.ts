import { randomBytes } from 'node:crypto';

export interface SessionOptions {
  idleMinutes: number;
}

export class SessionState {
  readonly brokerId = randomBytes(8).toString('hex');
  workspace: string | null = null;

  private lastActivity = 0;
  private inFlight = 0;

  constructor(private readonly opts: SessionOptions) {}

  bindWorkspace(cwd: string): boolean {
    if (this.workspace === null) {
      this.workspace = cwd;
      return true;
    }
    return this.workspace === cwd;
  }

  /**
   * Callers must only touch on AUTHORIZED activity. Unauthenticated calls
   * (secret_status, denied runs) must not refresh the clock, or an agent
   * could keep cached secrets alive past idleMinutes for free.
   */
  touch(now: number = Date.now()): void {
    this.lastActivity = now;
  }

  runStarted(): void {
    this.inFlight += 1;
  }

  runFinished(now: number = Date.now()): void {
    this.inFlight -= 1;
    this.lastActivity = now;
  }

  isIdle(now: number = Date.now()): boolean {
    if (this.inFlight > 0) return false;
    return now - this.lastActivity > this.opts.idleMinutes * 60_000;
  }
}
