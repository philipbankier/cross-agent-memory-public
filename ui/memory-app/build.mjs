import { build } from "esbuild";
import { readFile, readdir, mkdir, writeFile } from "node:fs/promises";

const result = await build({
  entryPoints: [new URL("src/app.ts", import.meta.url).pathname],
  bundle: true,
  write: false,
  format: "esm",
  target: "es2022",
  minify: true,
  legalComments: "inline",
  metafile: true,
});
const packages = new Set();
for (const [input, contribution] of Object.entries(
  Object.values(result.metafile.outputs)[0].inputs,
)) {
  if (contribution.bytesInOutput === 0) continue;
  if (!input.includes("node_modules/")) continue;
  const parts = input.split("node_modules/").at(-1).split("/");
  packages.add(parts.slice(0, parts[0].startsWith("@") ? 2 : 1).join("/"));
}
const notices = [];
for (const name of [...packages].sort()) {
  const root = new URL(`node_modules/${name}/`, import.meta.url);
  const files = (await readdir(root)).filter((file) =>
    ["LICENSE", "LICENSE.md", "LICENSE.txt", "license"].includes(file),
  );
  if (files.length !== 1)
    throw new Error(`Expected one bundled license for ${name}`);
  const license = await readFile(new URL(files[0], root), "utf8");
  if (license.includes("-->"))
    throw new Error("License cannot be embedded in HTML comment");
  notices.push(`${name}\n${license}`);
}
const template = await readFile(
  new URL("src/app.html", import.meta.url),
  "utf8",
);
const html =
  `<!-- Third-party license notices\n${notices.join("\n\n")}\n-->\n` +
  template.replace("/* APP_BUNDLE */", () =>
    result.outputFiles[0].text.replaceAll("</script", "<\\/script"),
  );
const output = new URL(
  "../../src/cross_assistant_memory/static/memory-app.html",
  import.meta.url,
);
if (process.argv.includes("--check")) {
  if ((await readFile(output, "utf8")) !== html)
    throw new Error(
      "Memory app bundle is stale; run npm run build in ui/memory-app",
    );
} else {
  await mkdir(new URL(".", output), { recursive: true });
  await writeFile(output, html);
}
