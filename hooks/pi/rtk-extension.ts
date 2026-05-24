/**
 * ContextCrawler — Pi extension.
 *
 * Rewrites bash commands to use contextcrawler for token savings before
 * Pi spawns them. Thin delegate: all rewrite logic lives in
 * `contextcrawler rewrite` (src/discover/registry.rs in the
 * ContextCrawler repo), which is the single source of truth. To change
 * rewrite rules, edit the Rust registry — not this file.
 *
 * Requires contextcrawler on PATH (with the rewrite subcommand).
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { createBashTool } from "@earendil-works/pi-coding-agent";
import { execFileSync, spawnSync } from "node:child_process";

const BINARY = "contextcrawler";

function binaryAvailable(): boolean {
	const result = spawnSync(BINARY, ["--version"], { stdio: "ignore" });
	return result.status === 0;
}

function rewrite(command: string): string {
	try {
		const out = execFileSync(BINARY, ["rewrite", command], {
			encoding: "utf8",
			stdio: ["ignore", "pipe", "ignore"],
		}).trim();
		return out || command;
	} catch {
		// rewrite failed — pass the original command through unchanged
		return command;
	}
}

export default function (pi: ExtensionAPI) {
	if (!binaryAvailable()) {
		console.warn(
			"[contextcrawler] binary not found on PATH — Pi extension disabled",
		);
		return;
	}

	pi.registerTool(
		createBashTool(process.cwd(), {
			spawnHook: ({ command, cwd, env }) => ({
				command: rewrite(command),
				cwd,
				env,
			}),
		}),
	);
}
