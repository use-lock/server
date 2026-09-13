<?php
declare(strict_types=1);

return [

    /*
    |--------------------------------------------------------------------------
    | Authentication Language Lines
    |--------------------------------------------------------------------------
    */

    'login' => [
        'title' => 'Log in',
        'heading' => 'Log in to your account',
        'subtitle' => 'Enter your email and password below to log in',
        'remember' => 'Remember me',
        'forgot-password' => 'Forgot your password?',
        'no-account' => "Don't have an account?",
        'sign-up' => 'Sign up',
        'social' => [
            'divider' => 'or continue with',
            'google' => 'Continue with Google',
            'apple' => 'Continue with Apple',
            'github' => 'Continue with GitHub',
            'fallback' => 'Continue with :provider',
        ],
    ],

    'register' => [
        'title' => 'Register',
        'heading' => 'Create an account',
        'subtitle' => 'Enter your details below to create your account',
        'submit' => 'Create account',
        'have-account' => 'Already have an account?',
    ],

    'forgot-password' => [
        'title' => 'Forgot password',
        'heading' => 'Forgot password',
        'subtitle' => 'Enter your email to receive a password reset link',
        'submit' => 'Email password reset link',
        'return' => 'Or, return to',
        'login-link' => 'log in',
    ],

    'reset-password' => [
        'title' => 'Reset password',
        'heading' => 'Reset your password',
        'subtitle' => 'Enter a new password for your account.',
        'submit' => 'Reset password',
    ],

    'update-password' => [
        'title' => 'Change password',
        'heading' => 'Change your password',
        'subtitle' => 'Choose a new password for your account.',
        'subtitle-expired' => 'Your password has expired. Choose a new one to continue.',
        'current' => 'Current password',
        'new' => 'New password',
        'submit' => 'Change password',
    ],

    'confirm-password' => [
        'title' => 'Confirm password',
        'heading' => 'Confirm password',
        'subtitle' => 'This is a secure area of the application. Please confirm your password before continuing.',
        'submit' => 'Confirm password',
        'passkey-label' => 'Confirm with passkey',
        'passkey-loading' => 'Confirming...',
        'passkey-separator' => 'Or confirm with password',
    ],

    'two-factor-setup' => [
        'title' => 'Two-factor authentication',
        'heading' => 'Set up two-factor authentication',
        'subtitle' => 'Add a second step to your sign-in.',
        'subtitle-required' => 'This account needs two-factor authentication before you can continue.',
        'continue' => 'Continue',
    ],

    'verify-email' => [
        'title' => 'Email verification',
        'heading' => 'Email verification',
        'subtitle' => 'Please verify your email address by clicking on the link we just emailed to you.',
        'resend' => 'Resend verification email',
        'sent' => 'A new verification link has been sent to the email address you provided during registration.',
    ],

    'two-factor' => [
        'title' => 'Two-factor authentication',
        'heading' => 'Two-factor authentication',
        'subtitle' => 'Enter the code from your authenticator app to continue',
        'continue' => 'Continue',
        'code' => 'Authentication code',
        'recovery-code' => 'Recovery code',
        'recovery-help' => 'Confirm access by entering one of your emergency recovery codes.',
        'use-recovery' => 'Use a recovery code instead',
        'subtitle-passkey' => 'Verify with your passkey to continue',
        'passkey-label' => 'Verify with a passkey',
        'passkey-loading' => 'Verifying...',
        'passkey-separator' => 'Or use a recovery code',
        'use-another' => 'Or use another method:',
        'method' => [
            'totp' => 'Authenticator app',
            'webauthn' => 'Passkey',
        ],
    ],

];
