import type {
  ProviderToolIdentification,
  ProviderVersionProbe,
} from "../application/reverse/ReverseEngineeringCommandPort.js";
import type { RizinInput } from "../domain/reverseEngineering.js";
import { absoluteCallerPath } from "../filesystem/callerPath.js";

export const RIZIN_PROVIDER_IDENTITY = {
  id: "rizin",
  name: "Rizin",
  version: null,
} as const;

/**
 * Read the `-v` banner of the executable that REA_RIZIN_COMMAND selected.
 * Rizin prints `rizin <version> @ <os>-<arch>-<bits>`. radare2 also accepts
 * REA's argument list, so another tool is recorded with a limitation rather
 * than refused.
 */
export const identifyRizinTool = (
  banner: string,
): ProviderToolIdentification => {
  const match = /^(\S+) (\d\S*)/u.exec(banner);
  const tool = match?.[1];
  const version = match?.[2];
  if (tool === undefined || version === undefined)
    return { identity: RIZIN_PROVIDER_IDENTITY, limitations: [] };
  if (tool === "rizin")
    return {
      identity: { ...RIZIN_PROVIDER_IDENTITY, version },
      limitations: [],
    };
  return {
    identity: { id: RIZIN_PROVIDER_IDENTITY.id, name: tool, version },
    limitations: [
      `REA_RIZIN_COMMAND selected ${tool} ${version}, not Rizin. REA ran it with Rizin's arguments; the output follows ${tool}'s command semantics, which REA has not verified.`,
    ],
  };
};

/** Identify the selected tool; the service reuses a completed probe per launch path and digest. */
export const RIZIN_VERSION_PROBE: ProviderVersionProbe = {
  arguments: ["-v"],
  identify: identifyRizinTool,
};

/** Default one-shot presentation to plain text while retaining plugin availability. */
export const rizinCommand = (input: RizinInput): readonly string[] => [
  "-N",
  "-q",
  "-e",
  "scr.color=0",
  "-c",
  input.command,
  absoluteCallerPath(input.path),
];
