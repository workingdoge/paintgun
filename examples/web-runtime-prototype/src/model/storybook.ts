import type { WebComponent } from "./runtime.ts";

export function storyArgTypes(component: WebComponent) {
  return Object.fromEntries(
    component.inputs.map((input) => {
      const control =
        input.kind === "boolean"
          ? "boolean"
          : {
              type: "inline-radio",
            };

      return [
        input.name,
        {
          control,
          ...(input.options ? { options: [...input.options] } : {}),
          description: input.description,
          table: {
            category: "web runtime input",
            defaultValue: {
              summary: String(input.default),
            },
          },
        },
      ];
    }),
  );
}
