<?php

declare(strict_types=1);

return [
    'resend-verification' => 'Resend verification email',
    'verification-sent' => 'A new verification link has been sent to your email address.',
    'already-verified' => 'Your email address is already verified.',

    'two-factor' => [
        'setup-key' => 'Or enter this setup key in your authenticator app:',
    ],

    'methods' => [
        'column' => 'Method',
        'role' => 'Good for',
        'last-used' => 'Last used',
        'never-used' => 'Never used',
        'last-used-at' => 'Last used :time',
        'remove' => 'Remove method',
        'remove-confirm-title' => 'Remove two-factor method?',
        'remove-confirm-description' => 'You will no longer be able to use this method during sign in.',
        'removed' => 'Two-factor method removed.',
    ],

    'setup' => [
        'step-method' => 'Method',
        'step-method-description' => 'How you want to prove it is you',
        'step-configure' => 'Set up',
        'step-configure-description' => 'Finish and confirm',
        'method' => 'How would you like to verify yourself?',
        'confirmation' => 'Confirmation',
        'confirmed' => ':method added.',
        'invalid' => 'That did not confirm the new method. Please try again.',
        'scan' => 'Scan this code with your authenticator app, then enter the six digits it shows.',
        'pick-method' => 'Pick a method in the previous step.',
        'device-name' => 'Name',
        'device-name-help' => 'Only for you, so you can tell this device apart later.',
        'create' => 'Continue',
        'creating' => 'Waiting for your browser…',
        'created' => 'Ready — finish to add it.',
        'cancelled' => 'Cancelled, or no matching device answered. Make sure your security key is plugged in, then try again.',
        'already-registered' => 'This device is already registered.',
        'failed' => 'That did not work. Please try again.',
        'unsupported' => 'This browser cannot create passkeys.',
    ],

    'role' => [
        'login-and-second-factor' => 'Sign-in + 2FA',
        'second-factor-only' => '2FA only',
        'backup' => 'Backup',
    ],

    'option' => [
        'passkey' => [
            'label' => 'Passkey',
            'description' => 'Face ID, Touch ID, or Windows Hello. Replaces your password at sign-in and counts as a second factor.',
        ],
        'security_key' => [
            'label' => 'Security key',
            'description' => 'A YubiKey or another FIDO2 key you plug in or tap.',
        ],
        'totp' => [
            'label' => 'Authenticator app',
            'description' => 'A six digit code from 1Password, Authy, Google Authenticator, or similar.',
        ],
    ],

    'recovery-codes' => [
        'heading' => 'Recovery codes',
        'remaining' => ':remaining of :total left',
        'regenerate' => 'Regenerate codes',
        'regenerate-confirm-title' => 'Regenerate recovery codes?',
        'regenerate-confirm-description' => 'Your existing recovery codes will stop working and be replaced with a new set.',
        'regenerated' => 'Recovery codes regenerated.',
        'description' => 'Store these recovery codes in a safe place. Each code can be used once to sign in if you lose access to your other methods.',
        'none' => 'There are no recovery codes to show. They are generated when you confirm your first two-factor method.',
    ],
];
