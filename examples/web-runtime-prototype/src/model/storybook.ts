import { buildValidationSummaryModel, type ValidationSummaryModel } from "./findings.ts";
import { buildComponentShowcaseModel, type ComponentShowcaseModel } from "./showcase.ts";
import type { WebComponent } from "./runtime.ts";
import { webRuntime } from "./runtime.ts";

export type StorybookOverviewModel = {
  componentShowcase: ComponentShowcaseModel;
  findings: ValidationSummaryModel;
  system: {
    id: string;
    release: string;
    sources: Array<{
      id: string;
      manifest: string;
      packId: string;
      packVersion: string;
      toolName: string;
      toolVersion: string;
    }>;
    title: string;
  };
};

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

export function buildStorybookOverviewModel(tagName = "paint-button"): StorybookOverviewModel {
  return {
    componentShowcase: buildComponentShowcaseModel(tagName),
    findings: buildValidationSummaryModel(),
    system: {
      id: webRuntime.webSystem.id,
      release: webRuntime.webSystem.release,
      sources: webRuntime.webSystem.paintSources.map((source) => ({
        id: source.id,
        manifest: source.manifest,
        packId: source.packIdentity.packId,
        packVersion: source.packIdentity.packVersion,
        toolName: source.tool.name,
        toolVersion: source.tool.version,
      })),
      title: webRuntime.webSystem.title,
    },
  };
}
