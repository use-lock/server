import { eagerComponent, type Plugin } from "@lattice-php/core/registry";
import PasskeyVerify from "./passkey-verify";
import TwoFactorSetup from "./two-factor-setup";

export default {
    name: "oidc-ui",
    components: {
        "oidc.passkey-verify": eagerComponent(PasskeyVerify),
        "field.oidc.two-factor-setup": eagerComponent(TwoFactorSetup),
    },
    i18n: {
        namespace: "oidc-ui",
    },
} satisfies Plugin;
