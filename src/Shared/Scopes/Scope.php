<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Scopes;

use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Contracts\Support\Jsonable;

/** @implements Arrayable<string, string> */
final readonly class Scope implements Arrayable, Jsonable
{
    public function __construct(
        public string $id,
        public string $description = '',
        public bool $hidden = false,
    ) {}

    /** @return array{id: string, description: string} */
    public function toArray(): array
    {
        return ['id' => $this->id, 'description' => $this->description];
    }

    public function toJson($options = 0): string
    {
        return (string) json_encode($this->toArray(), $options);
    }
}
