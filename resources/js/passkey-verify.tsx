import { router } from "@inertiajs/react";
import { usePasskeyVerify } from "@laravel/passkeys/react";
import type { RendererComponent } from "@lattice-php/core";
import { InputError } from "@lattice-php/form";
import { Button, Spinner } from "@lattice-php/ui";
import { useT } from "@lattice-php/ui/i18n";
import { IconRenderer } from "@lattice-php/ui/icons";

declare module "@lattice-php/core" {
    interface ComponentProps {
        "oidc.passkey-verify": {
            label?: string;
            loadingLabel?: string;
            optionsUrl: string;
            separator?: string;
            submitUrl: string;
        };
    }
}

const PasskeyVerify: RendererComponent<"oidc.passkey-verify"> = ({ node }) => {
    const { t } = useT("oidc-ui");
    const { verify, isLoading, error, isSupported } = usePasskeyVerify({
        routes: {
            options: node.props.optionsUrl,
            submit: node.props.submitUrl,
        },
        onSuccess: (response) => {
            if (response.redirect) {
                router.visit(response.redirect);
            }
        },
    });

    if (!isSupported) {
        return null;
    }

    return (
        <div className="mx-auto w-full max-w-md">
            <div className="grid gap-2">
                <Button
                    type="button"
                    emphasis="outline"
                    className="w-full"
                    onClick={verify}
                    disabled={isLoading}
                >
                    {isLoading ? (
                        <Spinner />
                    ) : (
                        <IconRenderer icon="key-round" className="h-4 w-4" />
                    )}
                    {isLoading
                        ? (node.props.loadingLabel ?? t("passkey.authenticating", "Authenticating..."))
                        : (node.props.label ?? t("passkey.sign-in", "Sign in with a passkey"))}
                </Button>
                {error && <InputError message={error} className="text-center" />}
            </div>

            <div className="relative my-6">
                <div className="absolute inset-0 flex items-center">
                    <div className="h-px w-full bg-lt-border" />
                </div>
                <div className="relative flex justify-center text-xs uppercase">
                    <span className="bg-lt-bg px-2 text-lt-muted-fg">
                        {node.props.separator ?? t("passkey.separator", "Or continue with email")}
                    </span>
                </div>
            </div>
        </div>
    );
};

export default PasskeyVerify;
