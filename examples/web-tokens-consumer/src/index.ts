import {
  PAINTGUN_WEB_TOKENS_API_VERSION,
  axes,
  contexts,
  spec,
  valuesByContext,
  type PaintTokenContext,
} from "paintgun-web-tokens";

export {
  PAINTGUN_WEB_TOKENS_API_VERSION,
  axes,
  contexts,
  spec,
  valuesByContext,
};

export type ConsumerInput = (typeof contexts)[number]["input"];
type ExampleTokenMap = (typeof valuesByContext)["mode:docs,theme:light"];
export type ConsumerTokenPath = keyof ExampleTokenMap;
export type ConsumerTokenRecord<Path extends ConsumerTokenPath = ConsumerTokenPath> =
  ExampleTokenMap[Path];
export type ConsumerTokenValue<Path extends ConsumerTokenPath = ConsumerTokenPath> =
  ConsumerTokenRecord<Path>["value"];

function stableInputKey(input: ConsumerInput): string {
  return Object.entries(input)
    .sort(([lhs], [rhs]) => lhs.localeCompare(rhs))
    .map(([axis, value]) => `${axis}:${value}`)
    .join(",");
}

const contextByInputKey = new Map(
  contexts.map((entry) => [stableInputKey(entry.input), entry.context as PaintTokenContext]),
);

export function availableInputs(): ConsumerInput[] {
  return contexts.map((entry) => entry.input);
}

export function resolveContext(input: ConsumerInput): PaintTokenContext {
  const key = stableInputKey(input);
  const context = contextByInputKey.get(key);
  if (context) {
    return context;
  }
  throw new Error(
    `unsupported token input ${key}; available inputs: ${availableInputs()
      .map((entry) => stableInputKey(entry))
      .join(" | ")}`,
  );
}

export function tokenMapFor(input: ConsumerInput): ExampleTokenMap {
  return valuesByContext[resolveContext(input)] as ExampleTokenMap;
}

export function tokenRecord<Path extends ConsumerTokenPath>(
  input: ConsumerInput,
  path: Path,
): ConsumerTokenRecord<Path> {
  return tokenMapFor(input)[path];
}

export function tokenValue<Path extends ConsumerTokenPath>(
  input: ConsumerInput,
  path: Path,
): ConsumerTokenValue<Path> {
  return tokenRecord(input, path).value;
}

export function buildSurfacePreview(input: ConsumerInput) {
  const context = resolveContext(input);
  const background = tokenValue(input, "color.surface.bg");
  const foreground = tokenValue(input, "color.text.primary");
  const radius = tokenValue(input, "dimension.radius.md");
  const duration = tokenValue(input, "duration.normal");

  return {
    apiVersion: PAINTGUN_WEB_TOKENS_API_VERSION,
    context,
    background: background.hex,
    foreground: foreground.hex,
    radius: `${radius.value}${radius.unit}`,
    duration: `${duration.value}${duration.unit}`,
  };
}
