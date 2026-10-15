import { type Generated, Kysely } from 'kysely';
import { DurableObjectDialect } from 'kysely-cloudflare';
import { type Migration, Migrator } from 'kysely/migration';

/** SQLite tables of a `Sandbox` Durable Object. */
export interface SandboxDatabase {
  snapshots: {
    id: string;
    name: string | null;
    size: number;
    auto: number;
    created_at: number;
  };
  backups: {
    id: string;
    name: string | null;
    dir: string;
    size: number;
    auto: number;
    created_at: number;
    /** JSON-encoded `DirectoryBackupRecord`. */
    record: string;
  };
  jobs: {
    id: string;
    command: string;
    cwd: string;
    status: 'running' | 'exited' | 'killed' | 'lost';
    exit_code: number | null;
    started_at: number;
    finished_at: number | null;
    timeout_s: number;
  };
  network_events: {
    seq: Generated<number>;
    ts: number;
    method: string;
    url: string;
    /** JSON-encoded header map. */
    headers: string;
    body_size: number;
    /** The first bytes of the body, encoded as `body_encoding` says. */
    body_preview: string;
    /** `utf8` or `base64`. Null in rows written before migration 0003 added it, which are UTF-8. */
    body_encoding: 'utf8' | 'base64' | null;
    /** Artifact key of the saved body, for bodies larger than the preview. */
    body_artifact: string | null;
    /** Status the sinkhole answered with. Null in rows written before migration 0002 added it. */
    response_status: number | null;
    /** Index of the sinkhole rule that matched, or null for the default answer. */
    rule: number | null;
  };
}

/** SQLite tables of a `SandboxRegistry` Durable Object. */
export interface RegistryDatabase {
  sandboxes: {
    name: string;
    network: string;
    instance: string;
    created_at: number;
  };
}

export const sandboxMigrations: Record<string, Migration> = {
  '0001_initial': {
    async up(db) {
      await db.schema
        .createTable('snapshots')
        .ifNotExists()
        .addColumn('id', 'text', (c) => c.primaryKey())
        .addColumn('name', 'text')
        .addColumn('size', 'integer', (c) => c.notNull())
        .addColumn('auto', 'integer', (c) => c.notNull())
        .addColumn('created_at', 'integer', (c) => c.notNull())
        .execute();
      await db.schema
        .createTable('backups')
        .ifNotExists()
        .addColumn('id', 'text', (c) => c.primaryKey())
        .addColumn('name', 'text')
        .addColumn('dir', 'text', (c) => c.notNull())
        .addColumn('size', 'integer', (c) => c.notNull())
        .addColumn('auto', 'integer', (c) => c.notNull())
        .addColumn('created_at', 'integer', (c) => c.notNull())
        .addColumn('record', 'text', (c) => c.notNull())
        .execute();
      await db.schema
        .createTable('jobs')
        .ifNotExists()
        .addColumn('id', 'text', (c) => c.primaryKey())
        .addColumn('command', 'text', (c) => c.notNull())
        .addColumn('cwd', 'text', (c) => c.notNull())
        .addColumn('status', 'text', (c) => c.notNull())
        .addColumn('exit_code', 'integer')
        .addColumn('started_at', 'integer', (c) => c.notNull())
        .addColumn('finished_at', 'integer')
        .addColumn('timeout_s', 'integer', (c) => c.notNull())
        .execute();
      await db.schema
        .createTable('network_events')
        .ifNotExists()
        .addColumn('seq', 'integer', (c) => c.primaryKey().autoIncrement())
        .addColumn('ts', 'integer', (c) => c.notNull())
        .addColumn('method', 'text', (c) => c.notNull())
        .addColumn('url', 'text', (c) => c.notNull())
        .addColumn('headers', 'text', (c) => c.notNull())
        .addColumn('body_size', 'integer', (c) => c.notNull())
        .addColumn('body_preview', 'text', (c) => c.notNull())
        .execute();
    },
  },
  '0002_sinkhole_answers': {
    async up(db) {
      await db.schema.alterTable('network_events').addColumn('response_status', 'integer').execute();
      await db.schema.alterTable('network_events').addColumn('rule', 'integer').execute();
    },
  },
  '0003_binary_body_preview': {
    async up(db) {
      await db.schema.alterTable('network_events').addColumn('body_encoding', 'text').execute();
    },
  },
  '0004_body_artifacts': {
    async up(db) {
      await db.schema.alterTable('network_events').addColumn('body_artifact', 'text').execute();
    },
  },
};

export const registryMigrations: Record<string, Migration> = {
  '0001_initial': {
    async up(db) {
      await db.schema
        .createTable('sandboxes')
        .ifNotExists()
        .addColumn('name', 'text', (c) => c.primaryKey())
        .addColumn('network', 'text', (c) => c.notNull())
        .addColumn('instance', 'text', (c) => c.notNull())
        .addColumn('created_at', 'integer', (c) => c.notNull())
        .execute();
    },
  },
};

/**
 * Opens the Durable Object's SQLite database and brings its schema up to date before the object
 * handles any request. Passing `ctx.storage` makes each migration run transactional.
 */
export function openDatabase<DB>(ctx: DurableObjectState, migrations: Record<string, Migration>): Kysely<DB> {
  const db = new Kysely<DB>({ dialect: new DurableObjectDialect({ database: ctx.storage }) });
  // Throwing inside blockConcurrencyWhile resets the Durable Object, so the next request retries.
  void ctx.blockConcurrencyWhile(() => migrate(db, migrations));
  return db;
}

export async function migrate(db: Kysely<any>, migrations: Record<string, Migration>): Promise<void> {
  const migrator = new Migrator({ db, provider: { getMigrations: async () => migrations } });
  const { error } = await migrator.migrateToLatest();
  if (error) {
    throw error;
  }
}
