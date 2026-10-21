// `sandbox.create`: one named container with its daemon, bound to one project
// and running the image it names, ready for mounts.
import { LayerFSError } from "../errors.js";
import { deployment, invoke } from "../client.js";

/**
 * `sandbox.create(name, project, image, { volumes })`: the Sandbox `name`
 * (unique in this LayerFS home), bound to `project` and running the image
 * digest `image`. Returns its name. The project's volume comes from this
 * client's deployment, so `project` must be this client's. `volumes`, optional,
 * is `[{ volume, target }]`: existing local volumes mounted read-only at
 * absolute `target`s outside every Workspace and LayerFS path (`/`,
 * `/workspaces`, `/layerfs-*`, `/proc`, `/sys`, `/dev` and `/tmp` are refused).
 * An entry's `readOnly`, if given, must be true.
 */
export async function create(client, name, project, image, { volumes = [] } = {}) {
  if (project !== client.projectName) {
    throw new LayerFSError("InvalidInput", `this client is for project ${client.projectName}; create a Sandbox of ${project} with a client of ${project}`, null);
  }
  if (!Array.isArray(volumes) || volumes.some((v) => v?.readOnly === false || typeof v?.volume !== "string" || typeof v?.target !== "string")) {
    throw new LayerFSError("InvalidInput", "volumes is a list of { volume, target }, each mounted read-only", null);
  }
  const mounts = volumes.map(({ volume, target }) => ({ volume, target }));
  const resolvedImage = image ?? (process.platform === "darwin" ? (client.options.deploy.image ?? `sha256:${"0".repeat(64)}`) : image);
  const value = await invoke("sandbox.create", { name, project, image: resolvedImage, volumes: mounts, home: client.options.home, deploy: deployment(client.options.deploy, false) }, client.options);
  client.sandboxes.add(value.id);
  return value.id;
}
