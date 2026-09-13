<?php

declare(strict_types=1);

return [
    'resend-verification' => 'Bestätigungs-E-Mail erneut senden',
    'verification-sent' => 'Ein neuer Bestätigungslink wurde an deine E-Mail-Adresse gesendet.',
    'already-verified' => 'Deine E-Mail-Adresse ist bereits bestätigt.',

    'two-factor' => [
        'setup-key' => 'Oder gib diesen Einrichtungsschlüssel in deiner Authenticator-App ein:',
    ],

    'methods' => [
        'column' => 'Methode',
        'role' => 'Gut für',
        'last-used' => 'Zuletzt verwendet',
        'never-used' => 'Nie verwendet',
        'last-used-at' => 'Zuletzt verwendet :time',
        'remove' => 'Methode entfernen',
        'remove-confirm-title' => 'Zwei-Faktor-Methode entfernen?',
        'remove-confirm-description' => 'Du kannst diese Methode dann nicht mehr bei der Anmeldung verwenden.',
        'removed' => 'Zwei-Faktor-Methode entfernt.',
    ],

    'setup' => [
        'step-method' => 'Methode',
        'step-method-description' => 'Womit du dich ausweisen möchtest',
        'step-configure' => 'Einrichten',
        'step-configure-description' => 'Abschließen und bestätigen',
        'method' => 'Wie möchtest du dich zusätzlich ausweisen?',
        'confirmation' => 'Bestätigung',
        'confirmed' => ':method hinzugefügt.',
        'invalid' => 'Damit ließ sich die neue Methode nicht bestätigen. Bitte versuche es erneut.',
        'scan' => 'Scanne den Code mit deiner Authenticator-App und gib die sechs Ziffern ein, die sie anzeigt.',
        'pick-method' => 'Wähle im vorherigen Schritt eine Methode.',
        'device-name' => 'Name',
        'device-name-help' => 'Nur für dich, damit du dieses Gerät später wiedererkennst.',
        'create' => 'Weiter',
        'creating' => 'Warte auf deinen Browser …',
        'created' => 'Bereit — klicke auf „Fertigstellen“, um die Methode hinzuzufügen.',
        'cancelled' => 'Abgebrochen, oder kein passendes Gerät hat geantwortet. Stelle sicher, dass dein Sicherheitsschlüssel eingesteckt ist, und versuche es erneut.',
        'already-registered' => 'Dieses Gerät ist bereits registriert.',
        'failed' => 'Das hat nicht funktioniert. Bitte versuche es erneut.',
        'unsupported' => 'Dieser Browser kann keine Passkeys erstellen.',
    ],

    'role' => [
        'login-and-second-factor' => 'Anmeldung + 2FA',
        'second-factor-only' => 'Nur 2FA',
        'backup' => 'Notfall',
    ],

    'option' => [
        'passkey' => [
            'label' => 'Passkey',
            'description' => 'Face ID, Touch ID oder Windows Hello. Ersetzt beim Anmelden das Passwort und zählt als zweiter Faktor.',
        ],
        'security_key' => [
            'label' => 'Sicherheitsschlüssel',
            'description' => 'Ein YubiKey oder ein anderer FIDO2-Schlüssel, den du einsteckst oder auflegst.',
        ],
        'totp' => [
            'label' => 'Authenticator-App',
            'description' => 'Ein sechsstelliger Code aus 1Password, Authy, Google Authenticator oder ähnlich.',
        ],
    ],

    'recovery-codes' => [
        'heading' => 'Wiederherstellungscodes',
        'remaining' => ':remaining von :total übrig',
        'regenerate' => 'Codes neu generieren',
        'regenerate-confirm-title' => 'Wiederherstellungscodes neu generieren?',
        'regenerate-confirm-description' => 'Deine bestehenden Wiederherstellungscodes werden ungültig und durch einen neuen Satz ersetzt.',
        'regenerated' => 'Wiederherstellungscodes neu generiert.',
        'description' => 'Bewahre diese Wiederherstellungscodes an einem sicheren Ort auf. Jeder Code kann einmal verwendet werden, falls du den Zugriff auf deine anderen Methoden verlierst.',
        'none' => 'Keine Wiederherstellungscodes vorhanden. Sie werden generiert, sobald du deine erste Zwei-Faktor-Methode bestätigst.',
    ],
];
