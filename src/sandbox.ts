import { DirectoryBackup, type DirectoryBackupRecord, Files, SandboxFileError } from '@cloudflare/sandbox';
import { DurableObject } from 'cloudflare:workers';
import { type Kysely, sql } from 'kysely';
import { batch } from 'kysely-cloudflare';
import { posix } from 'node:path';
import { migrate, openDatabase, type SandboxDatabase, sandboxMigrations } from './db';
import { capture, type CapturedOutput } from './output';
import { EMPTY_ANSWER, matchRule, type NetworkEvent, type SinkholeAnswer, type SinkholeRule } from './sinkhole';

export const NETWORK_MODES = ['offline', 'sinkhole', 'internet'] as const;
export type NetworkMode = (typeof NETWORK_MODES)[number];
// `lite` (256 MiB, 2 GB disk) is left out: the analysis image alone is about 1.7 GB, and the JVM
// tools need more memory.
export const INSTANCE_TYPES = ['standard-1', 'standard-2', 'standard-3', 'standard-4'] as const;
export type InstanceType = (typeof INSTANCE_TYPES)[number];

export interface SandboxConfig {
  principal: string;
  name: string;
  network: NetworkMode;
  instance: InstanceType;
  /** Back up /workspace to R2 when the sandbox stops (idle or sandbox_stop). */
  autoBackup: boolean;
  createdAt: number;
}

export interface ExecResult {
  exitCode: number;
  /** Signal that ended the command, from bash's 128+N exit status. */
  signal: number | null;
  timedOut: boolean;
  durationMs: number;
  stdout: CapturedOutput;
  stderr: CapturedOutput;
  notices: string[];
}

export interface JobInfo {
  id: string;
  command: string;
  cwd: string;
  status: 'running' | 'exited' | 'killed' | 'lost';
  exitCode: number | null;
  startedAt: number;
  finishedAt: number | null;
  timeoutSeconds: number;
}

export interface SnapshotInfo {
  id: string;
  name: string | null;
  size: number;
  auto: boolean;
  createdAt: number;
}

/** Written into the image at build time (/etc/sandbox-image.json); see container/Dockerfile. */
export interface ImageInfo {
  version: string;
  built: string;
  debian: string;
  tools: Record<string, string>;
  packages: Record<string, string>;
  python: Record<string, string>;
  /** Image reference this filesystem was first started from; snapshots keep it. */
  ref: string | null;
}

export interface BackupInfo {
  id: string;
  name: string | null;
  dir: string;
  size: number;
  auto: boolean;
  createdAt: number;
}

/**
 * How long the container outlives an inactive Durable Object. It must exceed CHECK_INTERVAL_MS, or
 * the container could stop between two alarms without being saved.
 */
const INACTIVITY_TIMEOUT_MS = 5 * 60 * 1000;
/** How often the alarm checks on a running sandbox. */
const CHECK_INTERVAL_MS = 60 * 1000;
/** A sandbox with no requests and no running jobs for this long is saved and stopped. */
const IDLE_LIMIT_MS = 15 * 60 * 1000;
/** A sandbox in use is snapshotted at most this often, to bound loss if it stops unexpectedly. */
const CHECKPOINT_INTERVAL_MS = 30 * 60 * 1000;
const AUTO_BACKUPS_KEPT = 3;
/** How often command results remind the agent that a newer image is available. */
const UPGRADE_NOTICE_INTERVAL_MS = 60 * 60 * 1000;
const NETWORK_EVENTS_KEPT = 5000;
/** Inline sinkhole bodies are stored with the rules; serve larger payloads from an artifact. */
const SINKHOLE_RULES_MAX_BYTES = 1024 * 1024;
const MAX_FETCH_BYTES = 1024 * 1024 * 1024;
const MAX_READ_BYTES = 4 * 1024 * 1024;
/** Snapshots expire 30 days after creation or last restore. */
const SNAPSHOT_TTL_MS = 30 * 24 * 60 * 60 * 1000;

const WORKSPACE = '/workspace';
const JOBS_DIR = '/var/lib/sandbox/jobs';
const CLOUDFLARE_CA = '/etc/cloudflare/certs/cloudflare-containers-ca.crt';
const SYSTEM_CA_BUNDLE = '/etc/ssl/certs/ca-certificates.crt';

/** `exec()` passes only PATH through from the image, so set the rest explicitly. */
const EXEC_ENV: Record<string, string> = {
  PATH: '/opt/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
  HOME: '/root',
  LANG: 'C.UTF-8',
  TERM: 'dumb',
  SSL_CERT_FILE: SYSTEM_CA_BUNDLE,
  REQUESTS_CA_BUNDLE: SYSTEM_CA_BUNDLE,
  NODE_EXTRA_CA_CERTS: CLOUDFLARE_CA,
};

// Trusts the Cloudflare CA so that HTTPS interception in `sinkhole` mode presents valid certificates.
const SETUP_SCRIPT = `
mkdir -p ${WORKSPACE} ${JOBS_DIR}
if [ -f ${CLOUDFLARE_CA} ] && command -v update-ca-certificates >/dev/null; then
  cp ${CLOUDFLARE_CA} /usr/local/share/ca-certificates/cloudflare-containers-ca.crt
  update-ca-certificates >/dev/null 2>&1 || true
fi
`;

// $1 job dir, $2 timeout seconds, $3 command, $4 cwd. setsid gives the job its own session so
// that sandbox_job_kill can signal everything it started. The exit file appears whole, via mv.
const JOB_START_SCRIPT = `
mkdir -p "$1" && cd "$4" || exit 1
setsid nohup bash -c 'timeout --kill-after=10 "$1" bash -c "$2"; echo $? > "$3/exit.tmp"; mv "$3/exit.tmp" "$3/exit"' _ "$2" "$3" "$1" >"$1/log" 2>&1 </dev/null &
echo $! > "$1/pid"
`;

// Prints a job's state: exit:<code>, running or lost. $1 job dir; $2 is "live" when the job's pid
// belongs to this instance, since a pid from an earlier instance may now be another process.
const JOB_STATE_FUNCTION = `
job_state() {
  if [ -f "$1/exit" ]; then echo "exit:$(cat "$1/exit")"
  elif [ "$2" = live ] && kill -0 "$(cat "$1/pid" 2>/dev/null)" 2>/dev/null; then echo running
  else echo lost; fi
}
`;

// $1 job dir, $2 tail bytes, $3 "live" or empty.
const JOB_STATUS_SCRIPT = `${JOB_STATE_FUNCTION}
job_state "$1" "$3"
echo "size:$(stat -c %s "$1/log" 2>/dev/null || echo 0)"
tail -c "$2" "$1/log" 2>/dev/null
`;

// $@ dirs of jobs started by this instance. Prints one state per line.
const JOBS_STATE_SCRIPT = `${JOB_STATE_FUNCTION}
for d in "$@"; do job_state "$d" live; done
`;

// $1 image reference, or empty when the instance started from a snapshot (which already has one).
const IMAGE_INFO_SCRIPT = `
[ -n "$1" ] && printf '%s' "$1" > /etc/sandbox-image-ref
cat /etc/sandbox-image.json 2>/dev/null || echo null
echo
cat /etc/sandbox-image-ref 2>/dev/null
`;

const JOB_KILL_SCRIPT = `
pid=$(cat "$1/pid" 2>/dev/null) || exit 0
pkill -TERM -s "$pid"; sleep 2; pkill -KILL -s "$pid"; true
`;

export class Sandbox extends DurableObject<Env> {
  readonly #db: Kysely<SandboxDatabase>;
  #filesApi: Files | null = null;
  #backupStore: DirectoryBackup | null = null;
  #setup: Promise<void> | null = null;
  #notices: string[] = [];
  /** Commands in flight. The alarm never saves or stops a sandbox while one runs. */
  #busy = 0;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.#db = openDatabase<SandboxDatabase>(ctx, sandboxMigrations);

    // A restarted Durable Object (for example after a deploy) starts without the inactivity timeout
    // and outbound intercepts of the container it left running. Restore them before any request,
    // so a sinkhole sandbox never goes unlogged.
    if (ctx.container?.running) {
      void ctx.blockConcurrencyWhile(async () => {
        const config = await ctx.storage.get<SandboxConfig>('config');
        if (config) {
          await this.#attach(config);
        }
      });
    }
  }

  // Metadata operations work without the container binding; only container work requires it.
  get #container(): Container {
    if (!this.ctx.container) {
      throw new Error('The container binding is not configured');
    }
    return this.ctx.container;
  }

  get #running(): boolean {
    return this.ctx.container?.running ?? false;
  }

  get #files(): Files {
    // ctx.container stays the same object while the Durable Object runs.
    this.#filesApi ??= new Files(this.#container);
    return this.#filesApi;
  }

  // ---------------------------------------------------------------------------------------------
  // Lifecycle

  async create(config: Omit<SandboxConfig, 'createdAt'>, cloneSnapshotId?: string): Promise<SandboxConfig> {
    if (await this.ctx.storage.get<SandboxConfig>('config')) {
      throw new Error(`Sandbox "${config.name}" already exists`);
    }
    const full: SandboxConfig = { ...config, createdAt: Date.now() };
    await this.ctx.storage.put('config', full);
    if (cloneSnapshotId) {
      await this.ctx.storage.put('snapshotId', cloneSnapshotId);
    }
    await this.#registry(full).put(full);
    return full;
  }

  async update(
    changes: Partial<Pick<SandboxConfig, 'network' | 'instance' | 'autoBackup'>>,
    upgradeImage = false,
  ): Promise<string[]> {
    const config = await this.#config();
    // Optional MCP arguments arrive as undefined; only apply the fields that were set.
    const set = Object.fromEntries(Object.entries(changes).filter(([, value]) => value !== undefined));
    const next: SandboxConfig = { ...config, ...set };
    await this.ctx.storage.put('config', next);
    await this.#registry(next).put(next);
    if (upgradeImage) {
      // The upgrade restarts the sandbox, which also applies the new settings.
      return this.#upgradeImage();
    }
    const restart = next.network !== config.network || next.instance !== config.instance;
    if (restart && this.#running) {
      const snapshot = await this.#snapshot('before-reconfigure', true);
      await this.#stopContainer('reconfigure');
      return [
        `Saved snapshot ${snapshot.id} and stopped the sandbox; the next command starts it with the new settings.`,
      ];
    }
    return [];
  }

  /**
   * Moves the sandbox to the currently deployed image. Snapshots keep the image they were taken
   * from, so this is the only way an existing sandbox gets new tools. /workspace is carried over
   * through an R2 backup; everything else (installed packages, files elsewhere) starts fresh. A
   * snapshot of the old state is kept so sandbox_restore can undo the upgrade.
   */
  async #upgradeImage(): Promise<string[]> {
    return this.#activity(async () => {
      const config = await this.#config();
      const deployed = this.#container.images.analysis!;
      const image = await this.ctx.storage.get<ImageInfo>('image');
      // A sandbox that never started has no image info, and starts from the current image unless
      // it was cloned from a snapshot.
      if (image ? image.ref === deployed : !(await this.ctx.storage.get('snapshotId'))) {
        return ['The sandbox already runs the current image.'];
      }
      const notices = await this.#ensureRunning();
      const backup = await this.#backup(config, WORKSPACE, 'before-upgrade', [], false);
      const snapshot = await this.#snapshot('before-upgrade', false);
      await this.#stopContainer('upgrade');
      // Start from the image, then restore the backup.
      await this.ctx.storage.delete('snapshotId');
      await this.ctx.storage.put('pendingRestore', backup.id);
      notices.push(...(await this.#ensureRunning()));
      notices.push(
        `Upgraded to ${deployed}. /workspace was carried over (R2 backup ${backup.id}); packages installed and files outside /workspace were not. Snapshot ${snapshot.id} holds the previous state; restore it with sandbox_restore to go back.`,
      );
      return notices;
    });
  }

  async status() {
    const config = await this.#config();
    const stored = await this.ctx.storage.get<number>(['lastActivity', 'instanceStartedAt', 'savedAt']);
    const image = (await this.ctx.storage.get<ImageInfo>('image')) ?? null;
    const deployedImage = this.ctx.container?.images.analysis ?? null;
    return {
      ...config,
      running: this.#running,
      instanceStartedAt: stored.get('instanceStartedAt') ?? null,
      lastActivity: stored.get('lastActivity') ?? null,
      lastSavedAt: stored.get('savedAt') ?? null,
      restoreSnapshotId: (await this.ctx.storage.get<string>('snapshotId')) ?? null,
      snapshots: await this.#listSnapshots(10),
      backups: await this.#listBackups(),
      jobs: (await this.#jobRows()).slice(0, 20),
      networkEvents: (await this.#db.selectFrom('network_events').select((eb) => eb.fn.countAll<number>().as('n'))
        .executeTakeFirstOrThrow()).n,
      sinkholeRules: await this.#sinkholeRules(),
      // What the sandbox's filesystem contains, read when it last started. Null until first start.
      image,
      // The image a fresh start would use. A snapshot keeps the image it was taken from.
      deployedImage,
      imageCurrent: image?.ref && deployedImage ? image.ref === deployedImage : null,
      upgrade: this.#upgradeHint(image, deployedImage),
    };
  }

  /**
   * Stops the container, optionally saving a snapshot (and an R2 backup when enabled) first.
   * @returns Notices for the agent.
   */
  async stop(save: boolean): Promise<string[]> {
    await this.#config();
    if (!this.#running) {
      return ['The sandbox is not running.'];
    }
    const notices: string[] = [];
    if (save) {
      notices.push(...(await this.#saveForStop('manual')));
    }
    await this.#stopContainer('stopped');
    notices.push('Stopped.');
    return notices;
  }

  /** Destroys the container and deletes all state, including R2 backups. Snapshots expire on their own. */
  async delete(): Promise<void> {
    const config = await this.#config();
    if (this.#running) {
      await this.#container.destroy('deleted');
    }
    for (const row of await this.#db.selectFrom('backups').select('record').execute()) {
      await this.#backupsStore(config).delete(JSON.parse(row.record) as DirectoryBackupRecord);
    }
    await this.#registry(config).remove(config.name);
    await this.ctx.storage.deleteAlarm();
    await this.ctx.storage.deleteAll();
    // deleteAll() drops the tables too; recreate them so the name can be reused right away.
    await migrate(this.#db, sandboxMigrations);
  }

  /**
   * The snapshot a clone of this sandbox should start from. A running sandbox is snapshotted
   * first, so the clone gets its current files.
   * @returns The snapshot id, or undefined if the sandbox has never been saved.
   */
  async cloneSource(): Promise<string | undefined> {
    await this.#config();
    if (this.#running) {
      return (await this.#snapshot('clone', false)).id;
    }
    return this.ctx.storage.get<string>('snapshotId');
  }

  // ---------------------------------------------------------------------------------------------
  // Commands

  async exec(
    options: { command: string; cwd: string; timeoutSeconds: number; stdin?: string; maxOutputBytes: number },
  ): Promise<ExecResult> {
    return this.#activity(async () => {
      const notices = await this.#ensureRunning();
      const upgrade = await this.#upgradeNotice();
      if (upgrade) {
        notices.push(upgrade);
      }
      const started = Date.now();
      const result = await this.#run([
        'timeout',
        '--kill-after=5',
        String(options.timeoutSeconds),
        'bash',
        '-c',
        options.command,
      ], {
        cwd: options.cwd,
        stdin: options.stdin,
        limit: options.maxOutputBytes,
        // Backstop in case `timeout` itself cannot stop the command.
        hardTimeoutMs: (options.timeoutSeconds + 30) * 1000,
      });
      const durationMs = Date.now() - started;
      return {
        ...result,
        signal: result.exitCode > 128 && result.exitCode < 160 ? result.exitCode - 128 : null,
        // `timeout` exits 124 after SIGTERM and 137 after SIGKILL; 137 alone could also be an OOM kill.
        timedOut: (result.exitCode === 124 || result.exitCode === 137) && durationMs >= options.timeoutSeconds * 1000,
        durationMs,
        notices,
      };
    });
  }

  async jobStart(options: { command: string; cwd: string; timeoutSeconds: number }): Promise<JobInfo> {
    return this.#activity(async () => {
      await this.#ensureRunning();
      const id = crypto.randomUUID().slice(0, 8);
      const { cwd } = options;
      const result = await this.#run([
        'bash',
        '-c',
        JOB_START_SCRIPT,
        '_',
        `${JOBS_DIR}/${id}`,
        String(options.timeoutSeconds),
        options.command,
        cwd,
      ], { limit: 4096 });
      if (result.exitCode !== 0) {
        throw new Error(`Could not start job: ${result.stderr.text || result.stdout.text}`);
      }
      const startedAt = Date.now();
      await this.#db.insertInto('jobs').values({
        id,
        command: options.command,
        cwd,
        status: 'running',
        started_at: startedAt,
        timeout_s: options.timeoutSeconds,
      }).execute();
      return this.#job(id);
    });
  }

  /**
   * Reads a job's state and the tail of its log. The log survives in snapshots, so reading it
   * starts a stopped sandbox; a state-only check (`tailBytes` 0) never does.
   */
  async jobStatus(id: string, tailBytes: number): Promise<{ job: JobInfo; logBytes: number; logTail: string }> {
    return this.#activity(async () => {
      let job = await this.#job(id);
      const live = this.#running && (await this.#jobFromCurrentInstance(job));
      // The alarm records the exit of every job before it stops an idle sandbox, so a job still
      // marked running in an earlier instance was cut off.
      if (job.status === 'running' && !live) {
        await this.#finishJob(id, 'lost', null);
        job = await this.#job(id);
      }
      if (!this.#running && tailBytes === 0) {
        return { job, logBytes: 0, logTail: '' };
      }
      await this.#ensureRunning();
      const result = await this.#run([
        'bash',
        '-c',
        JOB_STATUS_SCRIPT,
        '_',
        `${JOBS_DIR}/${id}`,
        String(tailBytes),
        live ? 'live' : '',
      ], { limit: tailBytes + 256 });
      const [state = '', size = '', ...rest] = result.stdout.text.split('\n');
      if (job.status === 'running') {
        await this.#recordJobState(id, state);
      }
      return { job: await this.#job(id), logBytes: Number(size.slice(5)) || 0, logTail: rest.join('\n') };
    });
  }

  async jobList(): Promise<JobInfo[]> {
    await this.#config();
    return this.#jobRows();
  }

  async jobKill(id: string): Promise<JobInfo> {
    return this.#activity(async () => {
      const job = await this.#job(id);
      if (job.status !== 'running') {
        return job;
      }
      if (this.#running && (await this.#jobFromCurrentInstance(job))) {
        await this.#ensureRunning();
        await this.#run(['bash', '-c', JOB_KILL_SCRIPT, '_', `${JOBS_DIR}/${id}`], { limit: 4096 });
      }
      await this.#finishJob(id, 'killed', null);
      return this.#job(id);
    });
  }

  // ---------------------------------------------------------------------------------------------
  // Files

  async writeFile(path: string, content: Uint8Array): Promise<{ path: string; size: number; sha256: string }> {
    return this.#activity(async () => {
      await this.#ensureRunning();
      await this.#mkdirParent(path);
      await this.#files.writeFile(path, content, { cwd: WORKSPACE });
      return {
        path,
        size: content.byteLength,
        sha256: new Uint8Array(await crypto.subtle.digest('SHA-256', content)).toHex(),
      };
    });
  }

  async readFile(path: string, offset: number, length: number): Promise<{ bytes: Uint8Array; size: number }> {
    return this.#activity(async () => {
      await this.#ensureRunning();
      const stat = await this.#files.stat(path, { cwd: WORKSPACE });
      if (stat.type !== 'file') {
        throw new Error(`${path} is a ${stat.type}, not a file`);
      }
      const count = Math.min(length, MAX_READ_BYTES);
      const process = await this.#container.exec([
        'dd',
        `if=${path}`,
        'bs=65536',
        'iflag=skip_bytes,count_bytes',
        `skip=${offset}`,
        `count=${count}`,
        'status=none',
      ], { cwd: WORKSPACE, env: EXEC_ENV, stderr: 'ignore' });
      // dd stops after `count` bytes, which bounds what this reads into memory.
      const [bytes, exitCode] = await Promise.all([new Response(process.stdout).bytes(), process.exitCode]);
      if (exitCode !== 0) {
        throw new Error(`Could not read ${path} (dd exited with ${exitCode})`);
      }
      return { bytes, size: Number(stat.size) };
    });
  }

  async listFiles(path: string, depth: number): Promise<CapturedOutput> {
    return this.#activity(async () => {
      await this.#ensureRunning();
      const result = await this.#run([
        'bash',
        '-c',
        `find "$1" -mindepth 1 -maxdepth "$2" -printf '%y %M %10s %TY-%Tm-%Td %TH:%TM  %p\\n' | LC_ALL=C sort -k6 | head -n 2000`,
        '_',
        // A leading '-' would make find parse the path as an expression such as -delete.
        path.startsWith('-') ? `./${path}` : path,
        String(depth),
      ], { cwd: WORKSPACE, limit: 256 * 1024 });
      if (result.exitCode !== 0 && !result.stdout.text) {
        throw new Error(result.stderr.text || `find exited with ${result.exitCode}`);
      }
      return result.stdout;
    });
  }

  /**
   * Downloads a URL from the Worker (not from the container, which may be offline) and streams it
   * into the sandbox. This is how samples get in without giving the sandbox network access.
   */
  async fetchUrl(url: string, path: string, headers: Record<string, string>) {
    return this.#activity(async () => {
      await this.#ensureRunning();
      const response = await fetch(url, { headers });
      if (!response.ok || !response.body) {
        throw new Error(`GET ${url} returned ${response.status} ${response.statusText}`);
      }
      if (Number(response.headers.get('content-length') ?? 0) > MAX_FETCH_BYTES) {
        throw new Error(`Response is larger than ${MAX_FETCH_BYTES} bytes`);
      }
      let size = 0;
      const limiter = new TransformStream<Uint8Array, Uint8Array>({
        transform(chunk, controller) {
          size += chunk.byteLength;
          if (size > MAX_FETCH_BYTES) {
            throw new Error(`Response is larger than ${MAX_FETCH_BYTES} bytes`);
          }
          controller.enqueue(chunk);
        },
      });
      const [toFile, toDigest] = response.body.pipeThrough(limiter).tee();
      const digest = new crypto.DigestStream('SHA-256');
      await this.#mkdirParent(path);
      await Promise.all([this.#files.writeFile(path, toFile, { cwd: WORKSPACE }), toDigest.pipeTo(digest)]);
      return {
        path,
        size,
        sha256: new Uint8Array(await digest.digest).toHex(),
        contentType: response.headers.get('content-type'),
        finalUrl: response.url,
      };
    });
  }

  /**
   * Copies a sandbox file to R2 under `artifacts/<principal>/<key>`. Directories, and files when
   * `zip` is set, are packed into a zip first, optionally encrypted (`infected` is the usual
   * password for malware samples).
   * @param zip Null to copy a file as is. Ignored for directories, which are always zipped.
   */
  async exportArtifact(path: string, key: string, zip: { password?: string } | null) {
    return this.#activity(async () => {
      const config = await this.#config();
      await this.#ensureRunning();
      const stat = await this.#files.stat(path, { cwd: WORKSPACE });
      if (stat.type !== 'file' && stat.type !== 'directory') {
        throw new Error(`${path} is a ${stat.type}; only files and directories can be exported`);
      }
      const archive = zip !== null || stat.type === 'directory';
      const source = archive ? `/tmp/export-${crypto.randomUUID()}.zip` : path;
      try {
        if (archive) {
          const absolute = posix.resolve(WORKSPACE, path);
          // Run from the parent so entries are stored as `<name>/...`, not absolute paths.
          await this.#runChecked([
            '7z',
            'a',
            '-tzip',
            '-y',
            '-bso0',
            '-bsp0',
            ...(zip?.password ? [`-p${zip.password}`] : []),
            // A name that starts with '-' would otherwise be read as a switch.
            '--',
            source,
            posix.basename(absolute),
          ], posix.dirname(absolute));
        }
        const size = Number((await this.#files.stat(source, { cwd: WORKSPACE })).size);
        const response = await this.#files.readFile(source, { cwd: WORKSPACE });
        const sized = new FixedLengthStream(size);
        const [object] = await Promise.all([
          this.env.BUCKET.put(artifactKey(config.principal, key), sized.readable, {
            customMetadata: { sandbox: config.name, path, ...(archive ? { format: 'zip' } : {}) },
          }),
          response.body!.pipeTo(sized.writable),
        ]);
        return { key, size, zipped: archive, encrypted: Boolean(zip?.password), etag: object.etag };
      } finally {
        if (archive) {
          await this.#files.remove(source, { force: true });
        }
      }
    });
  }

  /**
   * Copies an artifact from R2 into the sandbox. With `extract`, the artifact is unpacked into the
   * directory `path` instead (any format 7-Zip reads: zip, 7z, tar, gz, rar, ...).
   * @param extract Null to copy the artifact as a single file.
   */
  async importArtifact(key: string, path: string, extract: { password?: string } | null) {
    return this.#activity(async () => {
      const config = await this.#config();
      await this.#ensureRunning();
      const object = await this.env.BUCKET.get(artifactKey(config.principal, key));
      if (!object) {
        throw new Error(`Artifact "${key}" not found`);
      }
      if (!extract) {
        await this.#mkdirParent(path);
        await this.#files.writeFile(path, object.body, { cwd: WORKSPACE });
        return { key, path, size: object.size, extracted: false };
      }
      const archive = `/tmp/import-${crypto.randomUUID()}`;
      try {
        await this.#files.writeFile(archive, object.body);
        await this.#files.mkdir(path, { recursive: true, cwd: WORKSPACE });
        // Always pass -p so an encrypted archive without a password fails instead of prompting.
        await this.#runChecked(
          ['7z', 'x', '-y', '-bso0', '-bsp0', `-p${extract.password ?? ''}`, `-o${path}`, '--', archive],
          WORKSPACE,
        );
        return { key, path, size: object.size, extracted: true };
      } finally {
        await this.#files.remove(archive, { force: true });
      }
    });
  }

  // ---------------------------------------------------------------------------------------------
  // Persistence

  async saveSnapshot(name: string): Promise<SnapshotInfo> {
    return this.#activity(async () => {
      await this.#config();
      if (!this.#running) {
        throw new Error('The sandbox is not running, so it has no unsaved changes.');
      }
      await this.#ensureRunning();
      return this.#snapshot(name, false);
    });
  }

  async saveBackup(dir: string, name: string, exclude: string[]): Promise<BackupInfo> {
    return this.#activity(async () => {
      const config = await this.#config();
      await this.#ensureRunning();
      return this.#backup(config, dir, name, exclude, false);
    });
  }

  /**
   * Restores a snapshot (replacing the whole filesystem) or an R2 backup (replacing one directory).
   * @param saveCurrent Snapshot the running filesystem first. Only applies to snapshot restores.
   * @returns Notices for the agent.
   * @throws If `id` is neither a known snapshot nor a known backup.
   */
  async restore(id: string, saveCurrent: boolean): Promise<string[]> {
    return this.#activity(async () => {
      const config = await this.#config();
      const notices: string[] = [];
      const snapshot = await this.#db.selectFrom('snapshots').select('id').where('id', '=', id).executeTakeFirst();
      if (snapshot) {
        if (this.#running) {
          if (saveCurrent) {
            notices.push(
              `Saved the current filesystem as snapshot ${(await this.#snapshot('before-restore', true)).id}.`,
            );
          }
          await this.#stopContainer('restore');
        }
        await this.ctx.storage.put('snapshotId', id);
        notices.push(...(await this.#ensureRunning()));
        notices.push(`Restored snapshot ${id}. Processes and jobs from the previous instance are gone.`);
        return notices;
      }
      const backup = await this.#db.selectFrom('backups').select('record').where('id', '=', id).executeTakeFirst();
      if (!backup) {
        throw new Error(`No snapshot or backup with id ${id}`);
      }
      notices.push(...(await this.#ensureRunning()));
      const record = JSON.parse(backup.record) as DirectoryBackupRecord;
      await this.#backupsStore(config).restore(record);
      notices.push(`Restored backup ${id} into ${record.dir}.`);
      return notices;
    });
  }

  // ---------------------------------------------------------------------------------------------
  // Network sinkhole

  async setSinkholeRules(rules: SinkholeRule[]): Promise<SinkholeRule[]> {
    await this.#config();
    if (new TextEncoder().encode(JSON.stringify(rules)).byteLength > SINKHOLE_RULES_MAX_BYTES) {
      throw new Error('Sinkhole rules exceed 1 MiB; serve large bodies from an artifact instead');
    }
    for (const [index, rule] of rules.entries()) {
      try {
        // Builds the response once, so a rule that Response rejects fails now instead of per request.
        void new Response(rule.body === undefined && rule.artifact === undefined ? null : 'x', {
          status: rule.status,
          headers: rule.headers,
        });
        if (rule.body !== undefined && rule.artifact !== undefined) {
          throw new Error('set body or artifact, not both');
        }
        if (rule.bodyEncoding === 'base64' && rule.body !== undefined) {
          Uint8Array.fromBase64(rule.body);
        }
        try {
          void new URLPattern({ hostname: rule.host, pathname: rule.path });
        } catch {
          throw new Error('host or path is not a valid URLPattern; escape literal : ( ) { } ? + with a backslash');
        }
      } catch (error) {
        throw new Error(`Sinkhole rule ${index}: ${error instanceof Error ? error.message : String(error)}`, {
          cause: error,
        });
      }
    }
    await this.ctx.storage.put('sinkholeRules', rules);
    return rules;
  }

  /** Records a request a sinkhole sandbox made and decides how the sinkhole answers it. */
  async answerNetworkRequest(event: NetworkEvent): Promise<SinkholeAnswer> {
    const config = await this.ctx.storage.get<SandboxConfig>('config');
    const rules = await this.#sinkholeRules();
    const index = matchRule(rules, event.method, event.url);
    const rule = rules[index];
    let answer = EMPTY_ANSWER;
    if (config && rule) {
      answer = {
        status: rule.status,
        headers: rule.headers,
        body: rule.body === undefined
          ? null
          : rule.bodyEncoding === 'base64'
          ? Uint8Array.fromBase64(rule.body)
          : new TextEncoder().encode(rule.body),
        objectKey: rule.artifact === undefined ? null : artifactKey(config.principal, rule.artifact),
      };
    }
    await this.#recordNetworkEvent(event, answer.status, rule ? index : null);
    return answer;
  }

  async #sinkholeRules(): Promise<SinkholeRule[]> {
    return (await this.ctx.storage.get<SinkholeRule[]>('sinkholeRules')) ?? [];
  }

  async #recordNetworkEvent(event: NetworkEvent, responseStatus: number, rule: number | null): Promise<void> {
    await batch(
      this.#db,
      [
        this.#db.insertInto('network_events').values({
          ts: Date.now(),
          method: event.method,
          url: event.url,
          headers: JSON.stringify(event.headers),
          body_size: event.bodySize,
          body_preview: event.bodyPreview,
          body_encoding: event.bodyEncoding,
          body_artifact: event.bodyArtifact,
          response_status: responseStatus,
          rule,
        }).compile(),
        this.#db.deleteFrom('network_events').where(
          'seq',
          '<=',
          sql<number>`(SELECT MAX(seq) FROM network_events) - ${NETWORK_EVENTS_KEPT}`,
        ).compile(),
      ] as const,
    );
  }

  async networkLog(afterSeq: number, limit: number) {
    await this.#config();
    const rows = await this.#db.selectFrom('network_events').selectAll().where('seq', '>', afterSeq).orderBy('seq')
      .limit(limit).execute();
    return rows.map((row) => ({
      seq: row.seq,
      time: new Date(row.ts).toISOString(),
      method: row.method,
      url: row.url,
      headers: JSON.parse(row.headers) as Record<string, string>,
      bodySize: row.body_size,
      bodyPreview: row.body_preview,
      bodyEncoding: row.body_encoding ?? 'utf8',
      bodyArtifact: row.body_artifact,
      response: row.response_status === null ? null : { status: row.response_status, rule: row.rule },
    }));
  }

  // ---------------------------------------------------------------------------------------------
  // Autosave: save and stop idle sandboxes, checkpoint busy ones.

  override async alarm(): Promise<void> {
    const config = await this.ctx.storage.get<SandboxConfig>('config');
    if (!config || !this.#running) {
      return;
    }
    const lastActivity = (await this.ctx.storage.get<number>('lastActivity')) ?? 0;
    const savedAt = (await this.ctx.storage.get<number>('savedAt')) ?? 0;
    const jobsRunning = await this.#reconcileJobs();
    const now = Date.now();
    const idle = this.#busy === 0 && jobsRunning === 0 && now - lastActivity > IDLE_LIMIT_MS;
    const checkpoint = this.#busy === 0 && lastActivity > savedAt && now - savedAt > CHECKPOINT_INTERVAL_MS;

    if (idle) {
      await this.#saveForStop('auto');
      const activeDuringSave = this.#busy > 0 || (await this.ctx.storage.get<number>('lastActivity')) !== lastActivity;
      if (!activeDuringSave) {
        await this.#stopContainer('idle');
        return;
      }
    } else if (checkpoint) {
      await this.#snapshot('checkpoint', true);
    }

    await this.#container.setInactivityTimeout(INACTIVITY_TIMEOUT_MS);
    await this.ctx.storage.setAlarm(Date.now() + CHECK_INTERVAL_MS);
  }

  // ---------------------------------------------------------------------------------------------
  // Internals

  async #config(): Promise<SandboxConfig> {
    const config = await this.ctx.storage.get<SandboxConfig>('config');
    if (!config) {
      throw new Error('This sandbox does not exist. Create it with sandbox_create first.');
    }
    return config;
  }

  #registry(config: SandboxConfig) {
    return this.env.REGISTRY.getByName(config.principal);
  }

  #backupsStore(config: SandboxConfig): DirectoryBackup {
    this.#backupStore ??= new DirectoryBackup(this.#container, this.ctx.exports.DirectoryBackupGateway, {
      binding: 'BUCKET',
      prefix: `backups/${config.principal}/${config.name}/`,
    });
    return this.#backupStore;
  }

  async #activity<T>(fn: () => Promise<T>): Promise<T> {
    this.#busy++;
    await this.ctx.storage.put('lastActivity', Date.now());
    try {
      return await fn();
    } finally {
      this.#busy--;
      await this.ctx.storage.put('lastActivity', Date.now());
    }
  }

  /**
   * Starts the container if needed and reapplies per-instance setup. Returns what happened along the
   * way (a snapshot restored, a backup applied) since the last call.
   */
  async #ensureRunning(): Promise<string[]> {
    if (this.#setup === null || !this.#running) {
      this.#setup = this.#startAndSetUp().catch((error: unknown) => {
        this.#setup = null;
        throw error;
      });
    }
    await this.#setup;
    const notices = this.#notices;
    this.#notices = [];
    return notices;
  }

  async #startAndSetUp(): Promise<void> {
    const config = await this.#config();
    const container = this.#container;
    let started = false;
    let startedFromImage = false;

    if (!container.running) {
      const snapshotId = await this.ctx.storage.get<string>('snapshotId');
      started = true;
      if (snapshotId) {
        try {
          this.#start(config, { containerSnapshot: { id: snapshotId } });
          await this.#probe();
          this.#notices.push(`Started from snapshot ${snapshotId}.`);
        } catch (error) {
          if (!/snapshot/i.test(String(error))) {
            throw error;
          }
          // Snapshots expire 30 days after their last restore. Fall back to the image and the
          // latest R2 backup instead of failing forever.
          this.#notices.push(
            `Snapshot ${snapshotId} could not be restored (${String(error)}); started from the image.`,
          );
          await this.ctx.storage.delete('snapshotId');
          await this.ctx.storage.put('pendingRestore', 'latest');
          if (container.running) {
            await container.destroy('snapshot restore failed');
          }
          this.#start(config, { image: container.images.analysis! });
          await this.#probe();
          startedFromImage = true;
        }
      } else {
        this.#start(config, { image: container.images.analysis! });
        await this.#probe();
        startedFromImage = true;
      }
      await this.ctx.storage.put({ instanceStartedAt: Date.now(), savedAt: Date.now() });
    }

    await this.#attach(config);
    if (started) {
      const setup = await this.#run(['bash', '-c', SETUP_SCRIPT], { limit: 4096 });
      if (setup.exitCode !== 0) {
        throw new Error(`Sandbox setup failed: ${setup.stderr.text}`);
      }
      await this.#readImageInfo(startedFromImage ? container.images.analysis! : '');
    }
    // Outside `started` so that a restore that failed is retried by the next call.
    const pendingRestore = await this.ctx.storage.get<string>('pendingRestore');
    if (pendingRestore) {
      await this.#restoreWorkspace(config, pendingRestore);
      await this.ctx.storage.delete('pendingRestore');
    }
    if ((await this.ctx.storage.getAlarm()) === null) {
      await this.ctx.storage.setAlarm(Date.now() + CHECK_INTERVAL_MS);
    }
  }

  /** Settings that belong to this Durable Object's connection to a running container. */
  async #attach(config: SandboxConfig): Promise<void> {
    const container = this.#container;
    await container.setInactivityTimeout(INACTIVITY_TIMEOUT_MS);
    // The backup route must be registered before the sinkhole catch-all, or the catch-all takes it.
    await this.#backupsStore(config).intercept();
    if (config.network === 'sinkhole') {
      const sinkhole = this.ctx.exports.NetworkSinkhole({
        props: { sandboxId: this.ctx.id.toString(), owner: { principal: config.principal, name: config.name } },
      });
      await container.interceptAllOutboundHttp(sinkhole);
      await container.interceptOutboundHttps('*', sinkhole);
    }
  }

  #upgradeHint(image: ImageInfo | null, deployed: string | null): string | null {
    if (!image?.ref || !deployed || image.ref === deployed) {
      return null;
    }
    return 'A newer sandbox image is available. Upgrade when convenient with sandbox_update upgrade_image=true; it keeps /workspace but not installed packages or files elsewhere.';
  }

  /** The upgrade hint for command results, at most once per UPGRADE_NOTICE_INTERVAL_MS. */
  async #upgradeNotice(): Promise<string | null> {
    const hint = this.#upgradeHint(
      (await this.ctx.storage.get<ImageInfo>('image')) ?? null,
      this.ctx.container?.images.analysis ?? null,
    );
    const last = (await this.ctx.storage.get<number>('upgradeNoticeAt')) ?? 0;
    if (!hint || Date.now() - last < UPGRADE_NOTICE_INTERVAL_MS) {
      return null;
    }
    await this.ctx.storage.put('upgradeNoticeAt', Date.now());
    return hint;
  }

  #start(
    config: SandboxConfig,
    source: { image: string } | { containerSnapshot: ContainerSnapshotRestoreParams },
  ): void {
    this.#container.start({
      ...source,
      entrypoint: ['/usr/bin/tini', '-s', '--', 'sleep', 'infinity'],
      enableInternet: config.network === 'internet',
      instance: config.instance,
      labels: { sandbox: config.name },
    });
  }

  /** `exec()` waits for a starting container, so a trivial command confirms it came up. */
  async #probe(): Promise<void> {
    const process = await this.#container.exec(['true'], { stdout: 'ignore', stderr: 'ignore' });
    await process.exitCode;
  }

  /** Records which image and tool versions the sandbox's filesystem has, for sandbox_status. */
  async #readImageInfo(ref: string): Promise<void> {
    const result = await this.#run(['bash', '-c', IMAGE_INFO_SCRIPT, '_', ref], { limit: 256 * 1024 });
    const [json = 'null', storedRef = ''] = result.stdout.text.split('\n');
    try {
      const info = JSON.parse(json) as Omit<ImageInfo, 'ref'> | null;
      if (info) {
        await this.ctx.storage.put('image', { ...info, ref: storedRef.trim() || null });
        return;
      }
    } catch {
      // An unreadable manifest counts as none.
    }
    // No manifest: sandbox_status reports the image as unknown.
    await this.ctx.storage.delete('image');
  }

  /**
   * Restores a /workspace backup. When none exists, adds a notice and leaves the workspace as is.
   * @param id A backup id, or `latest` for the newest backup of /workspace.
   */
  async #restoreWorkspace(config: SandboxConfig, id: string): Promise<void> {
    let query = this.#db.selectFrom('backups').select(['id', 'record']).where('dir', '=', WORKSPACE);
    query = id === 'latest' ? query.orderBy('created_at', 'desc') : query.where('id', '=', id);
    const row = await query.executeTakeFirst();
    if (!row) {
      this.#notices.push('No R2 backup of /workspace exists, so the workspace starts empty.');
      return;
    }
    await this.#backupsStore(config).restore(JSON.parse(row.record) as DirectoryBackupRecord);
    this.#notices.push(`Restored /workspace from R2 backup ${row.id}.`);
  }

  /**
   * Runs `argv` in the container and waits for it to exit. A nonzero exit code is returned, not
   * thrown; use #runChecked when failure should throw.
   * @param options.limit Bytes of stdout and of stderr to keep, each; see OutputCapture.
   * @param options.hardTimeoutMs Abort the exec after this long, for when the command's own timeout
   *   fails.
   */
  async #run(
    argv: string[],
    options: { cwd?: string; stdin?: string; limit: number; hardTimeoutMs?: number },
  ): Promise<{ exitCode: number; stdout: CapturedOutput; stderr: CapturedOutput }> {
    const controller = new AbortController();
    const process = await this.#container.exec(argv, {
      cwd: options.cwd,
      env: EXEC_ENV,
      stdin: options.stdin === undefined ? undefined : new Blob([options.stdin]).stream(),
      signal: controller.signal,
    });
    // Aborting after the process exits raises an internal error, so stop the timer on exit.
    let timer: ReturnType<typeof setTimeout> | undefined;
    if (options.hardTimeoutMs) {
      timer = setTimeout(() => controller.abort(), options.hardTimeoutMs);
    }
    const exitCode = process.exitCode.finally(() => timer !== undefined && clearTimeout(timer));
    const [stdout, stderr, code] = await Promise.all([
      capture(process.stdout, options.limit),
      capture(process.stderr, options.limit),
      exitCode,
    ]);
    return { exitCode: code, stdout, stderr };
  }

  async #runChecked(argv: string[], cwd: string): Promise<void> {
    const result = await this.#run(argv, { cwd, limit: 8192 });
    if (result.exitCode !== 0) {
      throw new Error(
        `${argv[0]} exited with ${result.exitCode}: ${(result.stderr.text || result.stdout.text).trim()}`,
      );
    }
  }

  async #mkdirParent(path: string): Promise<void> {
    const parent = path.includes('/') ? path.slice(0, path.lastIndexOf('/')) : '';
    if (parent) {
      await this.#files.mkdir(parent, { recursive: true, cwd: WORKSPACE });
    }
  }

  async #snapshot(name: string, auto: boolean): Promise<SnapshotInfo> {
    const startedAt = Date.now();
    const snapshot = await this.#container.snapshotContainer({ name });
    await this.#db.insertInto('snapshots').values({
      id: snapshot.id,
      name,
      size: snapshot.size,
      auto: auto ? 1 : 0,
      created_at: startedAt,
    }).execute();
    await this.ctx.storage.put({ snapshotId: snapshot.id, savedAt: startedAt });
    // Forget records that have certainly expired, except the one a restore would use.
    await this.#db.deleteFrom('snapshots').where('created_at', '<', startedAt - SNAPSHOT_TTL_MS).where(
      'id',
      '!=',
      snapshot.id,
    ).execute();
    return { id: snapshot.id, name, size: snapshot.size, auto, createdAt: startedAt };
  }

  async #backup(
    config: SandboxConfig,
    dir: string,
    name: string,
    exclude: string[],
    auto: boolean,
  ): Promise<BackupInfo> {
    const record = await this.#backupsStore(config).backup({ dir, name, exclude });
    const createdAt = Date.now();
    await this.#db.insertInto('backups').values({
      id: record.id,
      name,
      dir: record.dir,
      size: record.size,
      auto: auto ? 1 : 0,
      created_at: createdAt,
      record: JSON.stringify(record),
    }).execute();
    if (auto) {
      await this.#pruneAutoBackups(config);
    }
    return { id: record.id, name, dir: record.dir, size: record.size, auto, createdAt };
  }

  async #pruneAutoBackups(config: SandboxConfig): Promise<void> {
    const stale = await this.#db.selectFrom('backups').select(['id', 'record']).where('auto', '=', 1).orderBy(
      'created_at',
      'desc',
    ).limit(-1).offset(AUTO_BACKUPS_KEPT).execute();
    for (const row of stale) {
      await this.#backupsStore(config).delete(JSON.parse(row.record) as DirectoryBackupRecord);
      await this.#db.deleteFrom('backups').where('id', '=', row.id).execute();
    }
  }

  /** Snapshot plus, when enabled, an R2 backup of /workspace that outlives the snapshot's 30 days. */
  async #saveForStop(reason: string): Promise<string[]> {
    const config = await this.#config();
    const notices = [`Saved snapshot ${(await this.#snapshot(reason, reason === 'auto')).id}.`];
    if (config.autoBackup) {
      try {
        const backup = await this.#backup(config, WORKSPACE, reason, [], true);
        notices.push(`Backed up /workspace to R2 as ${backup.id}.`);
      } catch (error) {
        if (!(SandboxFileError.is(error) && error.code === 'ENOENT')) {
          notices.push(`R2 backup failed: ${String(error)}`);
        }
      }
    }
    return notices;
  }

  async #stopContainer(reason: string): Promise<void> {
    await this.#container.destroy(reason);
    this.#setup = null;
    await this.ctx.storage.deleteAlarm();
  }

  /**
   * Records the exit of every job that has finished since it was last checked, so a sandbox that
   * stops afterwards still reports how its jobs ended.
   * @returns How many jobs are still running.
   */
  async #reconcileJobs(): Promise<number> {
    const live: JobInfo[] = [];
    for (const job of await this.#jobRows()) {
      if (job.status !== 'running') {
        continue;
      }
      if (await this.#jobFromCurrentInstance(job)) {
        live.push(job);
      } else {
        await this.#finishJob(job.id, 'lost', null);
      }
    }
    if (live.length === 0) {
      return 0;
    }
    const result = await this.#run([
      'bash',
      '-c',
      JOBS_STATE_SCRIPT,
      '_',
      ...live.map((j) => `${JOBS_DIR}/${j.id}`),
    ], { limit: 64 * live.length + 256 });
    const states = result.stdout.text.split('\n');
    let running = 0;
    for (const [index, job] of live.entries()) {
      const state = states[index] ?? '';
      if (state === 'running') {
        running++;
      } else {
        await this.#recordJobState(job.id, state);
      }
    }
    return running;
  }

  /** Applies a state printed by job_state to a job that is marked running. */
  async #recordJobState(id: string, state: string): Promise<void> {
    if (state.startsWith('exit:')) {
      const code = Number.parseInt(state.slice(5), 10);
      await this.#finishJob(id, 'exited', Number.isNaN(code) ? null : code);
    } else if (state === 'lost') {
      await this.#finishJob(id, 'lost', null);
    }
  }

  async #jobFromCurrentInstance(job: JobInfo): Promise<boolean> {
    const instanceStartedAt = (await this.ctx.storage.get<number>('instanceStartedAt')) ?? 0;
    return job.startedAt >= instanceStartedAt;
  }

  async #finishJob(id: string, status: JobInfo['status'], exitCode: number | null): Promise<void> {
    await this.#db.updateTable('jobs').set({ status, exit_code: exitCode, finished_at: Date.now() }).where(
      'id',
      '=',
      id,
    ).execute();
  }

  async #job(id: string): Promise<JobInfo> {
    const [job] = await this.#jobRows(id);
    if (!job) {
      throw new Error(`No job with id ${id}`);
    }
    return job;
  }

  async #jobRows(id?: string): Promise<JobInfo[]> {
    let query = this.#db.selectFrom('jobs').selectAll().orderBy('started_at', 'desc');
    if (id !== undefined) {
      query = query.where('id', '=', id);
    }
    return (await query.execute()).map((row) => ({
      id: row.id,
      command: row.command,
      cwd: row.cwd,
      status: row.status,
      exitCode: row.exit_code,
      startedAt: row.started_at,
      finishedAt: row.finished_at,
      timeoutSeconds: row.timeout_s,
    }));
  }

  async #listSnapshots(limit: number): Promise<SnapshotInfo[]> {
    const rows = await this.#db.selectFrom('snapshots').selectAll().orderBy('created_at', 'desc').limit(limit)
      .execute();
    return rows.map((row) => ({
      id: row.id,
      name: row.name,
      size: row.size,
      auto: row.auto === 1,
      createdAt: row.created_at,
    }));
  }

  async #listBackups(): Promise<BackupInfo[]> {
    const rows = await this.#db.selectFrom('backups').select(['id', 'name', 'dir', 'size', 'auto', 'created_at'])
      .orderBy('created_at', 'desc').execute();
    return rows.map((row) => ({
      id: row.id,
      name: row.name,
      dir: row.dir,
      size: row.size,
      auto: row.auto === 1,
      createdAt: row.created_at,
    }));
  }
}

export function artifactKey(principal: string, key: string): string {
  return `artifacts/${principal}/${key}`;
}
