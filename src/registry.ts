import { DurableObject } from 'cloudflare:workers';
import type { Kysely } from 'kysely';
import { openDatabase, type RegistryDatabase, registryMigrations } from './db';
import { deliverEvents, subscribe, type SubscriptionIdentity, type SubscriptionRequest, unsubscribe } from './events';

export interface SandboxEntry {
  name: string;
  network: string;
  instance: string;
  createdAt: number;
}

/**
 * One registry per principal, listing that principal's sandboxes. Each Sandbox Durable Object
 * is the source of truth for its own state; the registry only makes them enumerable.
 */
export class SandboxRegistry extends DurableObject<Env> {
  readonly #db: Kysely<RegistryDatabase>;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.#db = openDatabase<RegistryDatabase>(ctx, registryMigrations);
  }

  async put(entry: SandboxEntry): Promise<void> {
    await this.#db
      .insertInto('sandboxes')
      .values({ name: entry.name, network: entry.network, instance: entry.instance, created_at: entry.createdAt })
      .onConflict((oc) =>
        oc.column('name').doUpdateSet((eb) => ({
          network: eb.ref('excluded.network'),
          instance: eb.ref('excluded.instance'),
        }))
      )
      .execute();
  }

  async remove(name: string): Promise<void> {
    await this.#db.deleteFrom('sandboxes').where('name', '=', name).execute();
    const subscriptions = await this.ctx.storage.list<{ id: string; args: { name: string } }>({
      prefix: 'subscription:',
    });
    for (const [key, subscription] of subscriptions) {
      if (subscription.args.name === name) await this.ctx.storage.delete([key, `verified:${subscription.id}`]);
    }
  }

  async list(): Promise<SandboxEntry[]> {
    const rows = await this.#db.selectFrom('sandboxes').selectAll().orderBy('name').execute();
    return rows.map((row) => ({
      name: row.name,
      network: row.network,
      instance: row.instance,
      createdAt: row.created_at,
    }));
  }

  async subscribe(principal: string, request: SubscriptionRequest) {
    return subscribe(this.ctx, principal, request);
  }

  async unsubscribe(principal: string, request: SubscriptionIdentity): Promise<void> {
    await unsubscribe(this.ctx, principal, request);
  }

  override async alarm(): Promise<void> {
    await deliverEvents(this.ctx);
  }
}
