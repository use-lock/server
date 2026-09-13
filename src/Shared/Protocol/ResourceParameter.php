<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Protocol;

/**
 * RFC 8707 §2: each `resource` value is an absolute URI without a fragment;
 * the parameter may repeat. Absent means the realm default audience.
 */
final class ResourceParameter
{
    /** @return list<string> */
    public static function parse(mixed $value, ?string $redirectUri = null, ?string $state = null): array
    {
        $resources = array_values(is_array($value) ? $value : [$value]);

        foreach ($resources as $resource) {
            if ($resource === null) {
                continue;
            }

            if (! is_string($resource) || ! filter_var($resource, FILTER_VALIDATE_URL) || str_contains($resource, '#')) {
                throw OAuthServerException::invalidTarget('The resource parameter must be an absolute URI without a fragment.', $redirectUri, $state);
            }
        }

        /** @var list<string> $resources */
        $resources = array_values(array_unique(array_filter($resources, is_string(...))));

        return $resources;
    }
}
