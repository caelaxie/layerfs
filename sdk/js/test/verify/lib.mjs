// Shared setup, checks and receipts for the #327 VERIFICATION cases.
// Each case runs as its own command: a fresh volume, a fresh Init of the
// fixture, its own Sandboxes, and teardown of all of them. Nothing is retried.
import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { LayerFS } from "../../src/index.js";
import { LayerFSOperator } from "../../operator/index.js";

const HERE = dirname(fileURLToPath(import.meta.url));
export const REPO = join(HERE, "../../../..");
const FIXTURE = join(HERE, "../fixture/website");
const RECEIPTS = join(REPO, "core/target/issue327/verify");

/** The node runtime image built on the pinned image (#323), by digest. */
export const IMAGE = process.env.LAYERFS_IMAGE ?? "sha256:2d929c6d66c21c962febba8ede6ddb6405faefa057d3b4d21750de07fe81918b";
export const DAEMON = process.env.LAYERFS_DAEMON ?? (process.platform === "darwin" ? (existsSync(join(REPO, "core/target/release/layerfs-daemon")) ? join(REPO, "core/target/release/layerfs-daemon") : join(REPO, "core/target/debug/layerfs-daemon")) : join(REPO, "core/target/issue327/layerfs-daemon"));

function dockerSocket() {
  const host = execFileSync("docker", ["context", "inspect", "--format", "{{.Endpoints.docker.Host}}"], { encoding: "utf8" }).trim();
  if (!host.startsWith("unix://")) throw new Error("a local Unix Docker engine is required");
  return host.slice("unix://".length);
}

export async function setup(id, { project = "website" } = {}) {
  const stamp = `${id.toLowerCase()}-${Date.now().toString(36)}`;
  const work = mkdtempSync(join(tmpdir(), "layerfs-327-"));
  const volume = process.platform === "darwin" ? join(work, "volume") : `layerfs-327-${stamp}`;
  if (process.platform === "darwin") {
    mkdirSync(volume, { recursive: true, mode: 0o700 });
  } else {
    execFileSync("docker", ["volume", "create", volume], { stdio: "ignore" });
  }
  const source = join(work, "website");
  cpSync(FIXTURE, source, { recursive: true });
  mkdirSync(join(source, ".git"));
  writeFileSync(join(source, ".git/HEAD"), "ref: refs/heads/main\n");
  const deploy = {
    docker: process.platform === "darwin" ? join(work, "home", "_sandboxes") : dockerSocket(),
    image: IMAGE,
    volume,
    daemon: DAEMON,
  };
  Object.assign(process.env, {
    LAYERFS_HOME: join(work, "home"), LAYERFS_DOCKER: deploy.docker,
    LAYERFS_IMAGE: deploy.image, LAYERFS_VOLUME: deploy.volume, LAYERFS_DAEMON: deploy.daemon,
    ...(process.platform === "darwin" ? { LAYERFS_STORE_PATH: join(volume, "global/store.sqlite") } : {}),
  });
  const layerfs = new LayerFS(project);
  return { id, stamp, volume, work, source, deploy, layerfs, operator: new LayerFSOperator(layerfs), mounts: [], checks: [], notes: [] };
}

/** Records one check; a failed check fails the case but the case goes on. */
export function check(ctx, name, ok, detail) {
  ctx.checks.push({ name, ok: Boolean(ok), detail: detail === undefined ? null : detail });
  return Boolean(ok);
}

export function note(ctx, text) {
  ctx.notes.push(text);
}

/** The refusal a call ends with, or null when it succeeded. */
export async function refusal(promise) {
  try {
    await promise;
    return null;
  } catch (error) {
    if (error && error.code) return error;
    throw error;
  }
}

/** Mounts a Workspace and tracks it for teardown. */
export async function mount(ctx, sandbox, branch) {
  const path = await ctx.layerfs.sandbox.mount(sandbox, branch);
  const ws = { sandbox, path, branch };
  ctx.mounts.push(ws);
  return ws;
}

export function sh(ctx, ws, command, options) {
  return options?.background ? ctx.operator.process.start(ws.sandbox, ws.path, command) : ctx.layerfs.sandbox.exec(ws.sandbox, ws.path, command, options?.message);
}

export async function unmount(ctx, ws, options) {
  const value = await ctx.layerfs.sandbox.unmount(ws.sandbox, ws.path, options?.discard);
  ctx.mounts = ctx.mounts.filter((m) => m !== ws);
  return value;
}

export const head = async (ctx, branch) => {
  const { items } = await ctx.layerfs.project.list_branches();
  const found = items.find((item) => item.name === branch);
  return found ? found.head ?? null : undefined;
};

/** The container id of the Sandbox `name`, from its record directory. */
export const containerOf = (name) => readFileSync(join(process.env.LAYERFS_HOME, "_sandboxes", name, "container"), "utf8").trim();

/** Unmounts (discarding), closes every Sandbox, removes the volume and host files. */
export async function teardown(ctx) {
  const problems = [];
  for (const ws of ctx.mounts) {
    for (const process of (await ctx.operator.process.list(ws.sandbox).catch(() => ({ items: [] }))).items) {
      if (process.status === "running") await ctx.operator.process.cancel(ws.sandbox, process.id).catch((e) => problems.push(`cancel ${process.id}: ${e.message}`));
    }
    await ctx.layerfs.sandbox.unmount(ws.sandbox, ws.path, true).catch((e) => problems.push(`unmount ${ws.path}: ${e.message}`));
  }
  const containers = [];
  for (const id of [...ctx.layerfs.sandboxes]) {
    await ctx.layerfs.sandbox.close(id).catch((e) => {
      problems.push(`close ${id}: ${e.message}`);
      containers.push(id);
    });
  }
  await ctx.layerfs.close().catch((e) => problems.push(`store close: ${e.message}`));
  if (process.platform !== "darwin") {
    for (const id of containers) {
      // Our own test container: remove it so the volume can go.
      let short = id;
      try { short = containerOf(id); execFileSync("docker", ["rm", "-f", short], { stdio: "ignore" }); } catch (e) { problems.push(`docker rm ${short}`); }
    }
    try { execFileSync("docker", ["volume", "rm", ctx.volume], { stdio: "ignore" }); } catch (e) { problems.push(`volume rm ${ctx.volume}`); }
  }
  rmSync(ctx.work, { recursive: true, force: true });
  return problems;
}

export function receipt(ctx, outcome) {
  mkdirSync(RECEIPTS, { recursive: true });
  const commit = execFileSync("git", ["-C", REPO, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  const dirty = execFileSync("git", ["-C", REPO, "status", "--porcelain", "--untracked-files=no", "--", "sdk/js", "core/crates"], { encoding: "utf8" }).trim();
  const daemon = execFileSync("shasum", ["-a", "256", DAEMON], { encoding: "utf8" }).slice(0, 64);
  const record = { case: ctx.id, stamp: ctx.stamp, commit, dirty: dirty ? dirty.split("\n") : [], daemon, image: IMAGE, ...outcome, checks: ctx.checks, notes: ctx.notes };
  const path = join(RECEIPTS, `${ctx.stamp}.json`);
  writeFileSync(path, JSON.stringify(record, null, 2), { flag: "wx" });
  return path;
}
