# Web CSS Compatibility

This note defines the browser-support and fallback expectations for Paint's
`web-css-vars` backend.

It applies to:

- `tokens.css`
- `tokens.vars.css`
- `components.css`

## What The Backend Assumes

`web-css-vars` emits modern layered CSS, not a legacy-browser stylesheet.

Today that means:

- the token stylesheets use `@layer`
- the component stylesheet also uses `@layer`
- Paint does not flatten or strip layers for older browsers
- Paint does not emit a second fallback stylesheet for browsers that do not
  support layers

The compatibility bundle `tokens.css` is only a convenience bundle. It combines
`tokens.vars.css` and `components.css`, but it does not change the browser
feature floor.

## Layer Baseline

At minimum, consumers need browsers that support CSS cascade layers.

Treat this as the layer-only floor:

- Chrome / Edge 99+
- Firefox 97+
- Safari 15.4+

## Practical Alpha Baseline

The layer-only floor is not always the whole story.

Paint's common examples and policies keep authored color spaces in CSS
(`"css_color": "preserve-space"`), and the generated token stylesheets often
carry modern CSS color syntax rather than legacy hex-only output.

For current alpha use, the safe expectation is:

- target modern evergreen browsers
- test the concrete generated CSS in the browsers you intend to support
- do not assume legacy-browser compatibility from `web-css-vars`

For the repo's current OKLCH-heavy examples, a practical floor is:

- Chrome / Edge 111+
- Firefox 113+
- Safari 15.4+

That practical floor is an inference from the emitted CSS shape, not a promise
that every future `web-css-vars` output will require the same versions.

## Fallback Expectations

Paint does not currently provide:

- automatic legacy-browser fallbacks
- a no-`@layer` alternate stylesheet
- a postprocessed compatibility build
- consumer-side polyfills or runtime shims

If you need older-browser support, do it outside Paint:

- postprocess the emitted CSS in your own web pipeline
- generate a separate compatibility stylesheet in consumer tooling
- constrain your token/policy choices to the browser baseline you actually need

## Policy Note

`css_color: prefer-hex-if-present` can lower some color-compatibility risk when
your token data already includes hex values, but it does not remove the
`@layer` requirement and it does not guarantee that every emitted color can be
downleveled automatically.

## Consumer Rule

Treat `web-css-vars` as a modern-web backend.

If you need long-tail browser compatibility, add a consumer-owned CSS
compatibility step instead of assuming Paint core will downlevel these files for
you.
