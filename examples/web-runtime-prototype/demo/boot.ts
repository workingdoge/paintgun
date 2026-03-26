type DemoRuntimeModule = {
  startDemo(document: Document): Promise<void> | void;
};

type BootState = "loading" | "booting" | "ready" | "error";

type BootElements = {
  title: HTMLElement;
  lede: HTMLElement;
  status: HTMLElement;
  errorPanel: HTMLElement;
  errorMessage: HTMLElement;
  errorStack: HTMLElement;
};

type ImportRuntime = () => Promise<DemoRuntimeModule>;

function requiredElement(document: Document, id: string): HTMLElement {
  const node = document.getElementById(id);
  if (!node) {
    throw new Error(`demo host is missing required element #${id}`);
  }
  return node;
}

function bootElements(document: Document): BootElements {
  return {
    title: requiredElement(document, "demo-title"),
    lede: requiredElement(document, "demo-lede"),
    status: requiredElement(document, "demo-status"),
    errorPanel: requiredElement(document, "boot-error"),
    errorMessage: requiredElement(document, "boot-error-message"),
    errorStack: requiredElement(document, "boot-error-stack"),
  };
}

function describeError(error: unknown) {
  if (error instanceof Error) {
    return {
      message: error.message,
      stack: error.stack || error.message,
    };
  }

  return {
    message: String(error),
    stack: String(error),
  };
}

export function setBootState(document: Document, state: BootState, message: string) {
  document.body.dataset.demoState = state;
  bootElements(document).status.textContent = message;
}

export function renderBootError(document: Document, error: unknown) {
  const elements = bootElements(document);
  const details = describeError(error);

  document.body.dataset.demoState = "error";
  elements.title.textContent = "Demo failed to boot";
  elements.lede.textContent =
    "The browser host hit a runtime failure before the shared web runtime finished loading.";
  elements.status.textContent = "Browser host failed.";
  elements.errorPanel.hidden = false;
  elements.errorMessage.textContent = details.message;
  elements.errorStack.textContent = details.stack;
}

const importRuntime: ImportRuntime = () => import("./main.js");

export async function bootDemoHost(
  document: Document = globalThis.document,
  importer: ImportRuntime = importRuntime,
) {
  setBootState(document, "booting", "Booting shared web runtime host…");

  try {
    const runtime = await importer();
    await runtime.startDemo(document);
    setBootState(document, "ready", "Browser host loaded.");
    return { ok: true as const };
  } catch (error) {
    renderBootError(document, error);
    return { ok: false as const, error };
  }
}
