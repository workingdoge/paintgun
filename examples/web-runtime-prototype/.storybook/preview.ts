import type { Preview } from "@storybook/web-components-vite";

import { registerPaintPrototype } from "../src/register.ts";

registerPaintPrototype();

function ensureStylesheet(href: string) {
  if (typeof document === "undefined") {
    return;
  }

  const absoluteHref = new URL(href, document.baseURI).toString();
  const existing = document.head.querySelector<HTMLLinkElement>(
    `link[data-paint-runtime-href="${absoluteHref}"]`,
  );
  if (existing) {
    return;
  }

  const link = document.createElement("link");
  link.rel = "stylesheet";
  link.href = href;
  link.dataset.paintRuntimeHref = absoluteHref;
  document.head.append(link);
}

const preview: Preview = {
  parameters: {
    controls: {
      expanded: true,
    },
    options: {
      storySort: {
        order: ["Overview", "Components"],
      },
    },
  },
  decorators: [
    (story, context) => {
      const stylesheets = context.parameters.paintRuntime?.requiredStylesheets;
      if (Array.isArray(stylesheets)) {
        for (const href of stylesheets) {
          if (typeof href === "string") {
            ensureStylesheet(href);
          }
        }
      }

      return story();
    },
  ],
};

export default preview;
