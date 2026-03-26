import { getWebComponentByTagName } from "../generated/system-web.ts";

const component = getWebComponentByTagName("paint-button");
const partName = component.parts[0]?.name ?? "control";
const pressEventName = component.events[0]?.name ?? "paint-press";

const toneInput = component.inputs.find((input) => input.name === "tone");
const emphasisInput = component.inputs.find((input) => input.name === "emphasis");
const disabledInput = component.inputs.find((input) => input.name === "disabled");

if (!toneInput || !emphasisInput || !disabledInput) {
  throw new Error("paint-button runtime metadata is incomplete");
}

function normalizeEnum(
  value: string | null,
  options: readonly string[] | undefined,
  fallback: string | boolean,
) {
  const allowed = options ?? [];
  if (typeof fallback !== "string") {
    throw new Error("expected string fallback");
  }
  if (!value || !allowed.includes(value)) {
    return fallback;
  }
  return value;
}

function buttonStyles() {
  return `
    :host {
      display: inline-flex;
      vertical-align: middle;
    }

    button {
      all: unset;
      box-sizing: border-box;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-inline-size: 9rem;
      gap: var(--paintgun-dimension-space-sm);
      cursor: pointer;
      user-select: none;
      background: var(--paintgun-color-surface-bg);
      color: var(--paintgun-color-text-primary);
      border: 1px solid var(--paintgun-color-surface-border);
      border-radius: var(--paintgun-dimension-radius-md);
      padding-block: var(--paintgun-dimension-space-sm);
      padding-inline: var(--paintgun-dimension-space-md);
      transition:
        background-color var(--paintgun-duration-fast),
        color var(--paintgun-duration-fast),
        border-color var(--paintgun-duration-fast),
        box-shadow var(--paintgun-duration-fast);
    }

    button[data-tone="accent"] {
      box-shadow: 0 0 0 2px var(--paintgun-color-surface-border);
    }

    button[data-emphasis="outline"] {
      background: transparent;
    }

    button:disabled {
      cursor: not-allowed;
      opacity: 0.6;
      box-shadow: none;
    }
  `;
}

export class PaintButtonElement extends HTMLElement {
  static get observedAttributes() {
    return component.inputs.map((input) => input.attribute);
  }

  connectedCallback() {
    this.render();
  }

  attributeChangedCallback() {
    this.render();
  }

  get tone() {
    return normalizeEnum(this.getAttribute("tone"), toneInput.options, toneInput.default);
  }

  set tone(value: string) {
    this.setAttribute("tone", value);
  }

  get emphasis() {
    return normalizeEnum(
      this.getAttribute("emphasis"),
      emphasisInput.options,
      emphasisInput.default,
    );
  }

  set emphasis(value: string) {
    this.setAttribute("emphasis", value);
  }

  get disabled() {
    return this.hasAttribute("disabled");
  }

  set disabled(value: boolean) {
    if (value) {
      this.setAttribute("disabled", "");
    } else {
      this.removeAttribute("disabled");
    }
  }

  render() {
    const tone = this.tone;
    const emphasis = this.emphasis;
    const disabled = this.disabled;
    const shadow = this.shadowRoot ?? this.attachShadow({ mode: "open" });

    shadow.innerHTML = `
      <style>${buttonStyles()}</style>
      <button
        part="${partName}"
        type="button"
        data-tone="${tone}"
        data-emphasis="${emphasis}"
        ${disabled ? "disabled" : ""}
      >
        <slot>Paint Button</slot>
      </button>
    `;

    const button = shadow.children.item(1);
    if (!button) {
      throw new Error("paint-button failed to render its internal control");
    }

    button.addEventListener("click", () => {
      if (this.disabled) {
        return;
      }

      this.dispatchEvent(
        new CustomEvent(pressEventName, {
          detail: {
            tone: this.tone,
            emphasis: this.emphasis,
          },
          bubbles: true,
          composed: true,
        }),
      );
    });
  }
}

export function definePaintButton() {
  if (!customElements.get(component.tagName)) {
    customElements.define(component.tagName, PaintButtonElement);
  }
}
