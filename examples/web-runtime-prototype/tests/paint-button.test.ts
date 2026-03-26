import { beforeEach, describe, expect, test } from "bun:test";
import { registerPaintPrototype } from "../src/register.ts";

beforeEach(() => {
  document.body.innerHTML = "";
});

describe("paint-button", () => {
  test("renders from shared metadata and dispatches the authored custom event", () => {
    registerPaintPrototype();

    const element = document.createElement("paint-button");
    element.setAttribute("tone", "accent");
    element.setAttribute("emphasis", "outline");
    element.textContent = "Ship it";

    const seen: Array<{ tone: string; emphasis: string }> = [];
    element.addEventListener("paint-press", (event) => {
      seen.push((event as CustomEvent<{ tone: string; emphasis: string }>).detail);
    });

    document.body.append(element);

    const control = element.shadowRoot?.querySelector("button");
    expect(control).not.toBeNull();
    expect(control?.getAttribute("part")).toBe("control");
    expect(control?.getAttribute("data-tone")).toBe("accent");
    expect(control?.getAttribute("data-emphasis")).toBe("outline");

    (control as HTMLButtonElement).click();

    expect(seen).toEqual([{ tone: "accent", emphasis: "outline" }]);
  });

  test("suppresses the custom event while disabled", () => {
    registerPaintPrototype();

    const element = document.createElement("paint-button");
    element.setAttribute("disabled", "");
    document.body.append(element);

    let fired = false;
    element.addEventListener("paint-press", () => {
      fired = true;
    });

    const control = element.shadowRoot?.querySelector("button");
    (control as HTMLButtonElement).click();

    expect(fired).toBe(false);
  });
});
