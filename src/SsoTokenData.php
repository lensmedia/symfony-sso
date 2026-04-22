<?php

declare(strict_types=1);

namespace Lens\Bundle\LensSsoBundle;

final readonly class SsoTokenData
{
    public function __construct(
        public string $username,
        public ?string $targetPath = null,
        public ?string $origin = null,
    ) {
    }
}
