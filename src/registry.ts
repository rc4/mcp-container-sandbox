import { DurableObject } from 'cloudflare:workers';
import type { Kysely } from 'kysely';
import { openDatabase, type RegistryDatabase, registryMigrations } from './db';

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
}
