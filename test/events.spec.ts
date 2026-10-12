import { withEnv } from 'cloudflare:workers';
import { describe, expect, it, vi } from 'vitest';
import { deliverEvents, subscribe, type SubscriptionRequest, unsubscribe } from '../src/events';
import type { JobInfo } from '../src/sandbox';
import { sendWebhook } from '../src/webhook';

vi.mock('../src/webhook', async (original) => ({
  ...await original<typeof import('../src/webhook')>(),
  sendWebhook: vi.fn<typeof sendWebhook>(),
}));

const secret = `whsec_${new Uint8Array(32).fill(1).toBase64()}`;
const input = (overrides: Partial<SubscriptionRequest> = {}): SubscriptionRequest => ({
  name: 'sandbox.job.finished',
  arguments: { name: 'analysis', job_id: 'job-1' },
  delivery: { mode: 'webhook', url: 'https://receiver.example/callback', secret },
  ...overrides,
});

function fixture() {
  const values = new Map<string, unknown>();
  const storage = {
    get: async (key: string) => structuredClone(values.get(key)),
    put: async (key: string, value: unknown) => {
      values.set(key, structuredClone(value));
    },
    delete: async (keys: string | string[]) => {
      for (const key of [keys].flat()) values.delete(key);
    },
    list: async ({ prefix }: { prefix: string }) =>
      new Map(
        [...values].filter(([key]) => key.startsWith(prefix)).map(([key, value]) => [key, structuredClone(value)]),
      ),
    setAlarm: vi.fn<(at: number) => Promise<void>>().mockResolvedValue(),
    transaction: async <T>(callback: (storage: unknown) => Promise<T>) => callback(storage),
  };
  const ctx = { storage } as unknown as DurableObjectState;
  const jobs: JobInfo[] = [{
    id: 'job-1',
    command: 'scan',
    cwd: '/workspace',
    status: 'running',
    exitCode: null,
    startedAt: Date.now(),
    finishedAt: null,
    timeoutSeconds: 120,
  }];
  const sandbox = {
    status: vi.fn<() => Promise<object>>(async () => ({})),
    jobList: vi.fn<() => Promise<JobInfo[]>>(async () => structuredClone(jobs)),
    jobStatus: vi.fn<(id: string) => Promise<{ job: JobInfo }>>(async (id) => ({
      job: structuredClone(jobs.find((job) => job.id === id)!),
    })),
  };
  const getByName = vi.fn<(name: string) => typeof sandbox>(() => sandbox);
  const env = { MCP_TOKENS: 'alice:token-0123456789abcdef', SANDBOX: { getByName } } as unknown as Env;
  const webhook = vi.mocked(sendWebhook);
  webhook.mockReset();
  webhook.mockImplementation(async (_, __, payload) => new Response(JSON.stringify(payload)));
  return {
    ctx,
    env,
    jobs,
    sandbox,
    getByName,
    webhook,
    values,
    subscribe: (principal: string, request: SubscriptionRequest) =>
      withEnv(env, () => subscribe(ctx, principal, request)) as ReturnType<typeof subscribe>,
    unsubscribe: (principal: string, request: SubscriptionRequest) =>
      withEnv(env, () => unsubscribe(ctx, principal, request)) as Promise<void>,
    deliver: (state = ctx) => withEnv(env, () => deliverEvents(state)) as Promise<void>,
  };
}

describe('MCP event subscriptions', () => {
  it('verifies once, uses canonical identity and refreshes persisted state with secret rotation', async () => {
    const f = fixture();
    const first = await f.subscribe('alice', input({ ttlMs: 60_000 }));
    expect(f.getByName).toHaveBeenCalledWith('alice/analysis');
    expect(f.webhook).toHaveBeenCalledOnce();
    const refreshed = await f.subscribe(
      'alice',
      input({ arguments: { job_id: 'job-1', name: 'analysis' }, ttlMs: null }),
    );
    expect(refreshed.id).toBe(first.id);
    expect(refreshed.refreshBefore).not.toBeNull();
    expect(f.webhook).toHaveBeenCalledOnce();
    const newSecret = `whsec_${new Uint8Array(32).fill(2).toBase64()}`;
    await f.subscribe('alice', input({ delivery: { ...input().delivery, secret: newSecret } }));
    expect(f.webhook).toHaveBeenCalledTimes(2);
    expect(f.values.get(`subscription:${first.id}`)).toMatchObject({ secret: newSecret, oldSecret: secret });
    const other = await f.subscribe('bob', input());
    expect(other.id).not.toBe(first.id);
  });

  it('rejects a failed challenge before storing a subscription', async () => {
    const f = fixture();
    f.webhook.mockResolvedValue(new Response('{"challenge":"wrong"}'));
    await expect(f.subscribe('alice', input())).rejects.toMatchObject({
      code: -32015,
      data: { reason: 'challenge_failed' },
    });
    expect([...f.values.keys()].filter((key) => key.startsWith('subscription:'))).toEqual([]);
  });

  it('queues matching completions durably and retries with the original event identity', async () => {
    const f = fixture();
    const subscribed = await f.subscribe('alice', input());
    f.jobs[0]!.status = 'exited';
    f.jobs[0]!.exitCode = 0;
    f.jobs[0]!.finishedAt = Date.now();
    f.jobs.push({ ...f.jobs[0]!, id: 'not-subscribed' });
    f.webhook.mockReset().mockResolvedValue(new Response('', { status: 503 }));
    await f.deliver();
    expect(f.webhook).toHaveBeenCalledOnce();
    const [_, id, event] = f.webhook.mock.calls[0]!;
    expect(event).toMatchObject({
      eventId: id,
      data: { name: 'analysis', job_id: 'job-1', status: 'exited', exitCode: 0 },
      cursor: null,
    });
    const stored = f.values.get(`subscription:${subscribed.id}`) as { pending: { attempts: number; nextAt: number }[] };
    expect(stored.pending[0]!.attempts).toBe(1);
    stored.pending[0]!.nextAt = 0;
    f.webhook.mockResolvedValue(new Response('', { status: 200 }));
    // A new state object uses only persisted storage, as after a restart.
    await f.deliver({ storage: f.ctx.storage } as DurableObjectState);
    expect(f.webhook.mock.calls[1]![1]).toBe(id);
    await f.deliver();
    expect(f.webhook).toHaveBeenCalledTimes(2);
  });

  it('stops on unsubscribe, expiration, revoked credentials and permanent callback failure', async () => {
    for (const reason of ['unsubscribe', 'expire', 'revoke', 'gone', 'too-large']) {
      const f = fixture();
      const subscribed = await f.subscribe('alice', input());
      f.jobs[0]!.status = 'lost';
      f.jobs[0]!.finishedAt = Date.now();
      f.webhook.mockClear();
      if (reason === 'unsubscribe') {
        await f.unsubscribe('bob', input());
        await f.unsubscribe('alice', input());
        await f.unsubscribe('alice', input());
      }
      if (reason === 'expire') (f.values.get(`subscription:${subscribed.id}`) as { expires: number }).expires = 0;
      if (reason === 'revoke') f.env.MCP_TOKENS = '';
      if (reason === 'gone') f.webhook.mockResolvedValue(new Response('', { status: 410 }));
      if (reason === 'too-large') f.webhook.mockResolvedValue(new Response('', { status: 413 }));
      await f.deliver();
      await f.deliver();
      expect(f.webhook).toHaveBeenCalledTimes(reason === 'gone' || reason === 'too-large' ? 1 : 0);
    }
  });

  it('does not resurrect an unsubscribed subscription while delivery is in flight', async () => {
    const f = fixture();
    const subscribed = await f.subscribe('alice', input());
    f.jobs[0]!.status = 'killed';
    f.jobs[0]!.finishedAt = Date.now();
    f.webhook.mockImplementation(async () => {
      await f.unsubscribe('alice', input());
      return new Response('', { status: 503 });
    });
    await f.deliver();
    expect(f.values.has(`subscription:${subscribed.id}`)).toBe(false);
  });
});
