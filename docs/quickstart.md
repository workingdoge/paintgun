# Paint 10-Minute Quickstart

This is the narrow first-success walkthrough for Paint.

It is intentionally small:

1. install `paint`
2. build one pack
3. verify it with a deliberate failure
4. explain the witness
5. apply one concrete fix
6. rerun to green

If you are reading this from a repo checkout, the example inputs live in:

- `examples/quickstart/failing.resolver.json`
- `examples/quickstart/fixed.resolver.json`

## 1. Install `paint`

Use the public install path from [`docs/install.md`](install.md):

```bash
curl -fsSL https://raw.githubusercontent.com/workingdoge/paintgun/main/scripts/install_paint.sh -o install_paint.sh
bash install_paint.sh
paint --version
```

## 2. Build the intentionally broken example

This example has one deliberate problem: `theme:dark` is missing an explicit value for `color.action.primary`.

Run:

```bash
mkdir -p quickstart-dist
paint build \
  examples/quickstart/failing.resolver.json \
  --out quickstart-dist \
  --target web-tokens-ts \
  --format json
```

What to look at after the build:

- primary emitted token output: `quickstart-dist/tokens.ts`
- manifest to verify: `quickstart-dist/ctc.manifest.json`
- machine-readable findings: `quickstart-dist/validation.json`
- witness payload for `paint explain`: `quickstart-dist/ctc.witnesses.json`

## 3. Verify and see the failure

```bash
paint verify quickstart-dist/ctc.manifest.json --require-composable
```

This should fail because the pack is not fully composable yet.

## 4. Explain the witness

Grab the first witness id from `validation.json`:

```bash
witness_id=$(grep -m1 -o '"witnessId": "[^"]*"' quickstart-dist/validation.json | cut -d'"' -f4)
echo "$witness_id"
```

Then explain it:

```bash
paint explain "$witness_id" --witnesses quickstart-dist/ctc.witnesses.json
```

You should see:

- finding family: `Missing definition`
- technical kind: `gap`
- the failing context `theme:dark`
- the token path `/color/action/primary/$value`
- a next action telling you to author the missing value explicitly

## 5. Apply the fix

The fix is one authored change in the `theme.dark` context. The missing token is:

- `color.action.primary`

The fixed version in `examples/quickstart/fixed.resolver.json` adds:

```json
"dark": [
  {
    "color": {
      "$type": "color",
      "action": {
        "primary": {
          "$value": {
            "colorSpace": "oklch",
            "components": [0.58, 0.13, 250],
            "hex": "#6f86ff"
          }
        }
      }
    }
  }
]
```

## 6. Rebuild and verify to green

```bash
mkdir -p quickstart-dist-fixed
paint build \
  examples/quickstart/fixed.resolver.json \
  --out quickstart-dist-fixed \
  --target web-tokens-ts \
  --format json

paint verify quickstart-dist-fixed/ctc.manifest.json --require-composable
```

This should succeed.

## What you just proved

In one short flow, you exercised the main user path:

- install
- build
- verify
- explain
- fix
- verify again

That is the canonical first-success path described in [`docs/first_success_ux.md`](first_success_ux.md).
