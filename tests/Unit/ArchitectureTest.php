<?php

declare(strict_types=1);
use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Lock\Server\Credentials\Ui\Components\PasskeyVerify;
use Lock\Server\Credentials\Ui\Forms\TwoFactorSetupForm;
use Lock\Server\Credentials\Ui\Support\FactorMethodName;
use Lock\Server\SigningKeys\SigningKeyGenerator;

$server = 'Lock\Server';

/* Factories reference models bidirectionally, so they are excluded from the domain graph. */
$domains = [
    'Shared',
    'Realms',
    'Audit',
    'Credentials',
    'SigningKeys',
    'Brokering',
    'Clients',
    'Scopes',
    'Tokens',
    'Sessions',
    'Authentication',
    'Protocol',
    'Consents',
    'Support\\Setup',
    'Support\\Maintenance',
];

$allowedClasses = [
    'Support\\Setup' => [SigningKeyGenerator::class],
    'Authentication' => [
        PasskeyVerify::class,
        FactorMethodName::class,
        TwoFactorSetupForm::class,
    ],
];

arch('package code uses the date factory and Carbon interfaces')
    ->expect('Lock\Server')
    ->not->toUse([
        Carbon::class,
        CarbonImmutable::class,
        Illuminate\Support\Carbon::class,
    ]);

/* Empty namespaces pass architecture rules, so renamed domains must fail this map check. */
it('names every domain the package ships', function () use ($domains): void {
    $directories = array_map(basename(...), glob(__DIR__.'/../../src/*', GLOB_ONLYDIR) ?: []);

    $shipped = [...array_values(array_diff($directories, ['Support'])), 'Support\\Setup', 'Support\\Maintenance'];
    sort($shipped);

    $constrained = $domains;
    sort($constrained);

    expect($constrained)->toBe($shipped);
});

it('names every support area the package ships', function (): void {
    $areas = array_map(basename(...), glob(__DIR__.'/../../src/Support/*', GLOB_ONLYDIR) ?: []);
    sort($areas);

    expect($areas)->toBe(['Maintenance', 'Setup', 'Testing']);
});

foreach ($domains as $domain) {
    $allowedWithShared = $domain === 'Shared' ? [] : ['Shared'];
    $forbidden = [...array_values(array_diff($domains, $allowedWithShared, [$domain])), 'Support\\Testing'];

    if ($domain === 'Shared') {
        $forbidden[] = 'Support';
    }

    arch("{$domain} only depends on ".($allowedWithShared === [] ? 'nothing' : implode(', ', $allowedWithShared)))
        ->expect("{$server}\\{$domain}")
        ->not->toUse(array_map(fn (string $forbiddenDomain): string => "{$server}\\{$forbiddenDomain}", $forbidden))
        ->ignoring($allowedClasses[$domain] ?? []);
}
