import { availableInputs, buildSurfacePreview, tokenValue } from "./index";

const input = { mode: "docs", theme: "light" } as const;

console.log(
  JSON.stringify(
    {
      availableInputs: availableInputs(),
      preview: buildSurfacePreview(input),
      mutedText: tokenValue(input, "color.text.muted"),
    },
    null,
    2,
  ),
);
