import { valuesByContext } from "../../generated/paint/web/tokens.ts";

type TokenContext = keyof typeof valuesByContext;
type TokenRecord = (typeof valuesByContext)[TokenContext];
type TokenValue = TokenRecord[keyof TokenRecord];

export type TokenPreviewEntry = {
  detail: string | null;
  token: string;
  type: string;
  value: string;
};

function formatTokenValue(token: TokenValue): Omit<TokenPreviewEntry, "token"> {
  if (token.type === "color" && token.value && typeof token.value === "object") {
    const detail =
      "colorSpace" in token.value && typeof token.value.colorSpace === "string"
        ? token.value.colorSpace
        : null;
    const value =
      "hex" in token.value && typeof token.value.hex === "string"
        ? token.value.hex
        : JSON.stringify(token.value);
    return {
      detail,
      type: token.type,
      value,
    };
  }

  if (
    (token.type === "dimension" || token.type === "duration") &&
    token.value &&
    typeof token.value === "object" &&
    "value" in token.value &&
    typeof token.value.value === "string"
  ) {
    const unit =
      "unit" in token.value && typeof token.value.unit === "string" ? token.value.unit : "";
    return {
      detail: null,
      type: token.type,
      value: `${token.value.value}${unit}`,
    };
  }

  return {
    detail: null,
    type: token.type,
    value: JSON.stringify(token.value),
  };
}

export function tokenPreviewEntries(context: string, tokenNames: string[]): TokenPreviewEntry[] {
  const contextTokens = valuesByContext[context as keyof typeof valuesByContext];
  if (!contextTokens) {
    throw new Error(`unknown token preview context: ${context}`);
  }

  return tokenNames.map((tokenName) => {
    const token = contextTokens[tokenName as keyof typeof contextTokens];
    if (!token) {
      throw new Error(`missing token preview value for ${tokenName}`);
    }
    const preview = formatTokenValue(token);
    return {
      ...preview,
      token: tokenName,
    };
  });
}
