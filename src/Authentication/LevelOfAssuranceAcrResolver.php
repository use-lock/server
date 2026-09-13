<?php

declare(strict_types=1);

namespace Lock\Server\Authentication;

use Lock\Server\Shared\Authentication\AcrResolver;
use Lock\Server\Shared\Realms\RealmResolver;

/**
 * Two levels, chosen by the number of distinct methods in `amr`: one method
 * earns the realm's `single_factor` value, two or more its `multi_factor`
 * value (`login.acr_values`, `1` and `2` by default). No methods means no
 * `acr`.
 */
final readonly class LevelOfAssuranceAcrResolver implements AcrResolver
{
    public function __construct(private RealmResolver $realms) {}

    public function fromAmr(array $amr): ?string
    {
        if ($amr === []) {
            return null;
        }

        $values = $this->realms->current()->login()->acrValues;

        return count(array_unique($amr)) > 1 ? $values['multi_factor'] : $values['single_factor'];
    }

    public function supported(): array
    {
        $values = $this->realms->current()->login()->acrValues;

        return array_values(array_unique([$values['single_factor'], $values['multi_factor']]));
    }
}
