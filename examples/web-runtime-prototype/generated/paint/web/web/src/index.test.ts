import { valuesByContext } from "./index";

const base = valuesByContext["(base)"];
if (!base || Object.keys(base).length === 0) {
  throw new Error("expected base token context");
}
