import { contexts, valuesByContext } from "./index";

const firstContext = contexts[0]?.context;
if (!firstContext) {
  throw new Error("expected at least one emitted token context");
}
const tokens = valuesByContext[firstContext];
if (!tokens || Object.keys(tokens).length === 0) {
  throw new Error("expected emitted tokens for first context");
}
