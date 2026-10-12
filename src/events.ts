import { type McpServer, ProtocolError } from '@modelcontextprotocol/server';
import { env } from 'cloudflare:workers';
import { z } from 'zod';
import { parseTokens } from './auth';
import type { JobInfo } from './sandbox';
import { callbackUrl, sendWebhook, signingKey } from './webhook';

const FILTER = z.object({
  name: z.string().regex(/^[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$/).describe('Sandbox name to monitor'),
  job_id: z.string().min(1).optional().describe('Monitor only this background job; omit for all jobs in the sandbox'),
}).strict();
const IDENTITY = z.object({
  name: z.literal('sandbox.job.finished'),
  arguments: FILTER,
  delivery: z.object({ mode: z.literal('webhook'), url: z.url() }),
});
const SUBSCRIBE = IDENTITY.extend({
  delivery: z.object({ mode: z.literal('webhook'), url: z.url(), secret: z.string() }),
  ttlMs: z.number().int().positive().nullable().optional(),
  cursor: z.null().optional(),
});
export type SubscriptionRequest = z.infer<typeof SUBSCRIBE>;
export type SubscriptionIdentity = z.infer<typeof IDENTITY>;

interface Event {
  eventId: string;
  name: 'sandbox.job.finished';
  timestamp: string;
  data: {
    name: string;
    job_id: string;
    status: JobInfo['status'];
    exitCode: number | null;
    startedAt: number;
    finishedAt: number;
  };
  cursor: null;
}
interface Subscription {
  id: string;
  principal: string;
  args: z.infer<typeof FILTER>;
  url: string;
  secret: string;
  oldSecret?: string;
  rotateUntil?: number;
  expires: number;
  createdAt: number;
  seen: string[];
  pending: { event: Event; attempts: number; nextAt: number }[];
}

export function registerEvents(server: McpServer, principal: string): void {
  // Events are a draft extension not yet included in the SDK's capability type.
  const capabilities = { events: {}, tools: {} };
  server.server.registerCapabilities(capabilities);
  server.server.setRequestHandler(
    'events/list',
    { params: z.object({ cursor: z.undefined().optional() }) },
    async () => ({
      events: [{
        name: 'sandbox.job.finished',
        description:
          'A background job in your sandbox exited, was killed, or was lost after a container restart. Read its output with sandbox_job_status. Monitoring starts at subscription time; no replay.',
        delivery: ['webhook'],
        inputSchema: z.toJSONSchema(FILTER),
        payloadSchema: z.toJSONSchema(
          z.object({
            name: z.string(),
            job_id: z.string(),
            status: z.enum(['exited', 'killed', 'lost']),
            exitCode: z.number().int().nullable(),
            startedAt: z.number().int(),
            finishedAt: z.number().int(),
          }).strict(),
        ),
      }],
    }),
  );
  const registry = env.REGISTRY.getByName(principal);
  server.server.setRequestHandler(
    'events/subscribe',
    { params: SUBSCRIBE },
    async (params) => ({ ...await registry.subscribe(principal, params) }),
  );
  server.server.setRequestHandler('events/unsubscribe', { params: IDENTITY }, async (params) => {
    await registry.unsubscribe(principal, params);
    return {};
  });
}

async function subscriptionId(principal: string, request: SubscriptionIdentity): Promise<string> {
  // The filter has a fixed field order, so equivalent argument objects have the same identity.
  const identity = [principal, callbackUrl(request.delivery.url).href, request.name, {
    name: request.arguments.name,
    ...(request.arguments.job_id === undefined ? {} : { job_id: request.arguments.job_id }),
  }];
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(identity)));
  return `sub_${new Uint8Array(hash).toHex()}`;
}

export async function subscribe(ctx: DurableObjectState, principal: string, input: SubscriptionRequest) {
  const request = SUBSCRIBE.parse(input);
  signingKey(request.delivery.secret);
  const url = callbackUrl(request.delivery.url).href;
  const sandbox = env.SANDBOX.getByName(`${principal}/${request.arguments.name}`);
  await sandbox.status();
  if (request.arguments.job_id && !(await sandbox.jobList()).some((job) => job.id === request.arguments.job_id)) {
    throw new ProtocolError(-32602, 'Unknown background job');
  }
  const id = await subscriptionId(principal, request);
  const key = `subscription:${id}`;
  const now = Date.now();
  // Refresh with the same secret reuses verification for at most one hour.
  const verifiedKey = `verified:${id}`;
  const verified = await ctx.storage.get<{ secret: string; until: number }>(verifiedKey);
  if (!verified || verified.secret !== request.delivery.secret || verified.until <= now) {
    const challenge = crypto.randomUUID();
    try {
      const response = await sendWebhook(
        { id, url, secret: request.delivery.secret },
        `verify_${crypto.randomUUID()}`,
        { type: 'verification', challenge },
      );
      const echoed = (await response.json()) as { challenge?: unknown };
      const actual = new TextEncoder().encode(typeof echoed.challenge === 'string' ? echoed.challenge : '');
      const expected = new TextEncoder().encode(challenge);
      if (!response.ok || actual.length !== expected.length || !crypto.subtle.timingSafeEqual(actual, expected)) {
        throw new Error('challenge_failed');
      }
    } catch (error) {
      throw new ProtocolError(-32015, 'Callback verification failed', {
        reason: error instanceof Error && error.name === 'TimeoutError' ? 'timeout' : 'challenge_failed',
      });
    }
    await ctx.storage.put(verifiedKey, { secret: request.delivery.secret, until: now + 3_600_000 });
  }
  const expires = Date.now() + Math.min(request.ttlMs ?? 86_400_000, 7 * 86_400_000);
  await ctx.storage.transaction(async (storage) => {
    const existing = await storage.get<Subscription>(key);
    const active = existing && existing.expires > now ? existing : undefined;
    const subscription: Subscription = {
      id,
      principal,
      args: request.arguments,
      url,
      secret: request.delivery.secret,
      expires,
      createdAt: active?.createdAt ?? now,
      seen: active?.seen ?? [],
      pending: active?.pending ?? [],
      ...(active?.secret !== undefined && active.secret !== request.delivery.secret
        ? { oldSecret: active.secret, rotateUntil: now + 300_000 }
        : { oldSecret: active?.oldSecret, rotateUntil: active?.rotateUntil }),
    };
    await storage.put(key, subscription);
  });
  await ctx.storage.setAlarm(Date.now() + 1000);
  return { id, refreshBefore: new Date(expires).toISOString(), cursor: null, truncated: false };
}

export async function unsubscribe(
  ctx: DurableObjectState,
  principal: string,
  request: SubscriptionIdentity,
): Promise<void> {
  const id = await subscriptionId(principal, IDENTITY.parse(request));
  await ctx.storage.delete([`subscription:${id}`, `verified:${id}`]);
}

/** Durable alarms observe jobs without holding a client connection or keeping idle containers alive. */
export async function deliverEvents(ctx: DurableObjectState): Promise<void> {
  const subscriptions = await ctx.storage.list<Subscription>({ prefix: 'subscription:' });
  if (!subscriptions.size) return;
  // Schedule first: a failing sandbox or callback cannot strand the other subscriptions.
  await ctx.storage.setAlarm(Date.now() + 30_000);
  const principals = new Set(parseTokens(env.MCP_TOKENS).values());
  for (const [key, subscription] of subscriptions) {
    if (subscription.expires <= Date.now() || !principals.has(subscription.principal)) {
      await ctx.storage.delete([key, `verified:${subscription.id}`]);
      continue;
    }
    try {
      const sandbox = env.SANDBOX.getByName(`${subscription.principal}/${subscription.args.name}`);
      const jobs = await sandbox.jobList();
      for (let job of jobs) {
        if (subscription.args.job_id && job.id !== subscription.args.job_id) continue;
        if (job.status === 'running') job = (await sandbox.jobStatus(job.id, 0)).job;
        if (job.status === 'running' || job.finishedAt === null || job.finishedAt < subscription.createdAt) continue;
        const eventId =
          `evt_${subscription.principal}_${subscription.args.name}_${job.id}_${job.startedAt}_${job.status}`;
        if (subscription.seen.includes(eventId)) continue;
        subscription.seen.push(eventId);
        subscription.pending.push({
          event: {
            eventId,
            name: 'sandbox.job.finished',
            timestamp: new Date(job.finishedAt).toISOString(),
            cursor: null,
            data: {
              name: subscription.args.name,
              job_id: job.id,
              status: job.status,
              exitCode: job.exitCode,
              startedAt: job.startedAt,
              finishedAt: job.finishedAt,
            },
          },
          attempts: 0,
          nextAt: Date.now(),
        });
      }
    } catch {
      console.warn('MCP job monitoring failed', { subscriptionId: subscription.id, sandbox: subscription.args.name });
      continue;
    }
    // Keep refreshes and unsubscribe authoritative while sandbox RPCs and webhook requests yield.
    const queued = await ctx.storage.transaction(async (storage) => {
      const current = await storage.get<Subscription>(key);
      if (!current || current.createdAt !== subscription.createdAt || current.expires <= Date.now()) return;
      for (const pending of subscription.pending) {
        if (!current.seen.includes(pending.event.eventId)) {
          current.seen.push(pending.event.eventId);
          current.pending.push(pending);
        }
      }
      await storage.put(key, current);
      return current;
    });
    if (!queued) continue;
    for (const pending of queued.pending) {
      if (pending.nextAt > Date.now()) continue;
      const current = await ctx.storage.get<Subscription>(key);
      if (!current || current.createdAt !== queued.createdAt || current.expires <= Date.now()) break;
      let status = 0;
      try {
        status = (await sendWebhook(current, pending.event.eventId, pending.event)).status;
      } catch { /* A connection failure is transient. */ }
      await ctx.storage.transaction(async (storage) => {
        const latest = await storage.get<Subscription>(key);
        if (!latest || latest.createdAt !== queued.createdAt) return;
        if (status === 410) {
          await storage.delete([key, `verified:${latest.id}`]);
          return;
        }
        const item = latest.pending.find((entry) => entry.event.eventId === pending.event.eventId);
        if (!item) return;
        item.attempts++;
        if (status < 200 || status >= 300) {
          console.warn('MCP webhook delivery failed', {
            subscriptionId: latest.id,
            eventId: item.event.eventId,
            status,
            attempt: item.attempts,
          });
        }
        const done = status >= 200 && status < 300
          || (status >= 300 && status < 500 && status !== 408 && status !== 429) || item.attempts >= 5;
        if (done) latest.pending = latest.pending.filter((entry) => entry !== item);
        else item.nextAt = Date.now() + 30_000 * 2 ** (item.attempts - 1);
        await storage.put(key, latest);
      });
    }
  }
}
