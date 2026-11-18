import type { TermixApp } from "@termix-ssh/plugin-sdk/frontend";
import { TotpEnrollment } from "./TotpEnrollment";

export function activate(app: TermixApp): void {
  app.registerSecondFactorUI({
    id: "totp",
    titleKey: "title",
    enrollment: TotpEnrollment,
  });
}
