<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Audit;

/**
 * Dotted values begin with the category (auth, oauth, admin).
 * Hosts extend the audit trail with their own backed enum.
 */
enum AuditEventType: string
{
    case LoginSucceeded = 'auth.login.succeeded';
    case LoginFailed = 'auth.login.failed';
    case LoggedOut = 'auth.logout';
    case UserRegistered = 'auth.registration.succeeded';
    case PasswordReset = 'auth.password.reset';
    case PasswordChanged = 'auth.password.changed';
    case MfaChallengeSucceeded = 'auth.mfa.challenge_succeeded';
    case MfaChallengeFailed = 'auth.mfa.challenge_failed';
    case RecoveryCodeUsed = 'auth.mfa.recovery_code_used';
    case FactorEnrollmentStarted = 'auth.mfa.factor_enrollment_started';
    case FactorConfirmed = 'auth.mfa.factor_confirmed';
    case FactorRevoked = 'auth.mfa.factor_revoked';
    case ConsentApproved = 'oauth.consent.approved';
    case ConsentDenied = 'oauth.consent.denied';
    case TokenIssued = 'oauth.token.issued';
    case TokenIssuanceFailed = 'oauth.token.failed';
    case TokenRevoked = 'oauth.token.revoked';
    case ClientAuthenticationFailed = 'oauth.client_auth.failed';
    case ClientRegistered = 'admin.client.registered';
    case ClientProvisioned = 'admin.client.provisioned';
    case KeysRotated = 'admin.keys.rotated';
}
