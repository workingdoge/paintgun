import { Window } from "happy-dom";

const windowInstance = new Window({
  url: "https://paint.example/",
});

Object.assign(globalThis, {
  window: windowInstance,
  document: windowInstance.document,
  HTMLElement: windowInstance.HTMLElement,
  customElements: windowInstance.customElements,
  CustomEvent: windowInstance.CustomEvent,
  Event: windowInstance.Event,
  Node: windowInstance.Node,
  ShadowRoot: windowInstance.ShadowRoot,
  HTMLButtonElement: windowInstance.HTMLButtonElement,
});

Object.assign(windowInstance, {
  SyntaxError,
});
