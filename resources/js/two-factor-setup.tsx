import { browserSupportsWebAuthn, startRegistration } from "@simplewebauthn/browser";
import { useEffect, useState } from "react";
import type { RendererComponent } from "@lattice-php/core";
import { SimpleField } from "@lattice-php/form/components/base/simple-field";
import type { ControlledField } from "@lattice-php/form/hooks/use-controlled-field";
import { useResolvedNode } from "@lattice-php/form/hooks/resolved-nodes";
import { fieldProps } from "@lattice-php/form/lib/field-props";
import { Input, InputError, InputOTP, Label } from "@lattice-php/form";
import { Button } from "@lattice-php/ui";
import { useT } from "@lattice-php/ui/i18n";

declare module "@lattice-php/core" {
    interface ComponentProps {
        "field.oidc.two-factor-setup": {
            kind: string | null;
            qrSvg: string | null;
            secret: string | null;
            otpLength: number;
            webauthnOptions: Record<string, unknown> | null;
            enrollmentId: string | null;
        };
    }
}

type Translate = (key: string, fallback: string) => string;

/**
 * What the browser throws is written for a developer reading a console, not for
 * someone deciding what to do next — and it arrives in the browser's language,
 * not the app's. `NotAllowedError` in particular covers everything from "you
 * closed the dialog" to "no security key is plugged in", so it earns a sentence
 * that names both.
 */
function ceremonyError(caught: unknown, t: Translate): string {
    const name = caught instanceof Error ? caught.name : "";

    if (name === "NotAllowedError" || name === "AbortError") {
        return t(
            "security.setup.cancelled",
            "Cancelled, or no matching device answered. Make sure your security key is plugged in, then try again.",
        );
    }

    if (name === "InvalidStateError") {
        return t("security.setup.already-registered", "This device is already registered.");
    }

    return t("security.setup.failed", "That did not work. Please try again.");
}

/**
 * Step two of the setup wizard. The server has already begun the enrollment and
 * put its payload in this field's props, so nothing here talks to an endpoint of
 * its own: whatever proves the setup — a typed code, or a credential the browser
 * mints — is written into the form value and travels with the wizard's single
 * submit.
 */
function CodeSetup({
    field,
    length,
    qrSvg,
    secret,
    t,
}: {
    field: ControlledField;
    length: number;
    qrSvg: string | null;
    secret: string | null;
    t: Translate;
}) {
    return (
        <div className="space-y-4">
            <p className="text-sm text-lt-muted-fg">
                {t(
                    "security.setup.scan",
                    "Scan this code with your authenticator app, then enter the six digits it shows.",
                )}
            </p>

            {qrSvg && (
                <div className="flex justify-center">
                    {/* Generated server-side by BaconQrCode from our own enrollment, never user input. */}
                    <div
                        className="rounded-lt bg-white p-3"
                        dangerouslySetInnerHTML={{ __html: qrSvg }}
                    />
                </div>
            )}

            {secret && (
                <div className="space-y-1">
                    <p className="text-xs text-lt-muted-fg">
                        {t(
                            "security.two-factor.setup-key",
                            "Or enter this setup key in your authenticator app:",
                        )}
                    </p>
                    <code className="block rounded-lt bg-lt-muted px-3 py-2 font-mono text-xs break-all">
                        {secret}
                    </code>
                </div>
            )}

            <div className="flex justify-center">
                <InputOTP
                    data-test={field.testId}
                    disabled={field.disabled || field.readOnly}
                    length={length}
                    name={field.name}
                    onChange={(next) => field.commit(next)}
                    value={field.value}
                />
            </div>
        </div>
    );
}

function CeremonySetup({
    field,
    options,
    t,
}: {
    field: ControlledField;
    options: Record<string, unknown> | null;
    t: Translate;
}) {
    const [name, setName] = useState("");
    const [credential, setCredential] = useState<unknown>(null);
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<string | null>(null);

    // The value carries both halves: the attestation the browser produced and the
    // label the user typed for it, which cannot have been known when the server
    // began the ceremony. The store commit drives resolves and precognition; the
    // hidden inputs below are what the submit actually serializes.
    useEffect(() => {
        field.commit(credential === null ? "" : { credential, name });
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [credential, name]);

    async function run(): Promise<void> {
        if (!options) {
            return;
        }

        setBusy(true);
        setError(null);

        try {
            setCredential(await startRegistration({ optionsJSON: options as never }));
        } catch (caught) {
            setCredential(null);
            setError(ceremonyError(caught, t));
        } finally {
            setBusy(false);
        }
    }

    if (!browserSupportsWebAuthn()) {
        return (
            <p className="text-sm text-lt-muted-fg">
                {t("security.setup.unsupported", "This browser cannot create passkeys.")}
            </p>
        );
    }

    return (
        <div className="space-y-4">
            <div className="grid gap-2">
                <Label htmlFor={`${field.name}-name`}>
                    {t("security.setup.device-name", "Name")}
                </Label>
                <Input
                    autoFocus
                    id={`${field.name}-name`}
                    onChange={(event) => setName(event.target.value)}
                    type="text"
                    value={name}
                />
                <p className="text-xs text-lt-muted-fg">
                    {t(
                        "security.setup.device-name-help",
                        "Only for you, so you can tell this device apart later.",
                    )}
                </p>
            </div>

            {credential === null ? (
                <Button data-test={field.testId} disabled={busy || !options} onClick={run}>
                    {busy
                        ? t("security.setup.creating", "Waiting for your browser…")
                        : t("security.setup.create", "Continue")}
                </Button>
            ) : (
                <>
                    <p className="text-sm" data-test={`${field.testId}-ready`}>
                        {t("security.setup.created", "Ready — finish to add it.")}
                    </p>
                    {/* Inertia serializes the live DOM on submit, so the ceremony's
                        result must be mounted as inputs — the store commit above never
                        reaches the wire. Mounted only once a credential exists, so the
                        server's `required` rule still gates an unfinished ceremony. */}
                    <input
                        name={`${field.name}[credential]`}
                        type="hidden"
                        value={JSON.stringify(credential)}
                    />
                    <input name={`${field.name}[name]`} type="hidden" value={name} />
                </>
            )}

            {error !== null && <InputError message={error} />}
        </div>
    );
}

const TwoFactorSetup: RendererComponent<"field.oidc.two-factor-setup"> = ({ node }) => {
    const { t } = useT("oidc-ui");
    // The payload only exists after the resolve `option` triggers; the node the
    // renderer hands down still carries the schema's empty props.
    const props = useResolvedNode(node).props;

    return (
        <SimpleField label={fieldProps(node).label ?? ""} node={node}>
            {(field) => {
                if (props.kind === "code") {
                    return (
                        <CodeSetup
                            field={field}
                            length={props.otpLength}
                            qrSvg={props.qrSvg}
                            secret={props.secret}
                            t={t}
                        />
                    );
                }

                if (props.kind === "ceremony") {
                    return <CeremonySetup field={field} options={props.webauthnOptions} t={t} />;
                }

                return (
                    <p className="text-sm text-lt-muted-fg">
                        {t("security.setup.pick-method", "Pick a method in the previous step.")}
                    </p>
                );
            }}
        </SimpleField>
    );
};

export default TwoFactorSetup;
