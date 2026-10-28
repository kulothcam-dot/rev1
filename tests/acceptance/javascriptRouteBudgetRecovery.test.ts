import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect } from "vitest";

import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";
import { cliTest } from "../support/cli/cliFixture.js";

cliTest(
  "recovers an oversized retained route page by selecting fields",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-route-budget-recovery-");
    const source = join(root, "app.js");
    const bundle = join(root, "parent.json");
    const route = `/api/${"a".repeat(1_100_000)}`;
    await writeFile(source, `router.push(${JSON.stringify(route)});\n`);
    const analyzed = await cli.run({
      arguments: [
        "analyze-javascript-application",
        root,
        "--evidence_output",
        bundle,
        "--json",
      ],
      timeoutMs: 60_000,
    });
    expect(analyzed.exitCode, analyzed.stderr).toBe(0);
    const request = (fields?: readonly string[]) =>
      JSON.stringify({
        source: { kind: "evidence-file", path: bundle },
        view: {
          kind: "javascript-routes",
          collection: "routes",
          limit: 1,
          ...(fields === undefined ? {} : { fields }),
        },
      });
    const wide = await cli.run({
      arguments: ["inspect-analysis-view", request(), "--json"],
    });
    expect(wide.exitCode).toBe(1);
    expect(wide.json).toMatchObject({
      code: "resource_constraint",
      retryable: false,
      details: { reported_limits: { limit_bytes: 1024 * 1024 } },
    });
    const wideError = wide.json as { remediation: { action: string } };
    expect(wideError.remediation.action).toContain("select fewer fields");
    expect(wideError.remediation.action).toContain("no runtime override");
    const narrow = await cli.run({
      arguments: [
        "inspect-analysis-view",
        request(["classification", "confidence"]),
        "--json",
      ],
    });
    expect(narrow.exitCode, narrow.stderr).toBe(0);
    expect(narrow.json).toMatchObject({
      normalized_result: {
        items: [expect.not.objectContaining({ path: expect.anything() })],
      },
    });
    expect(await readFile(bundle, "utf8")).toContain(route);
  },
);
