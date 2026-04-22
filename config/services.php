<?php

declare(strict_types=1);

namespace Symfony\Component\DependencyInjection\Loader\Configurator;

use Lens\Bundle\LensSsoBundle\Security\SsoAuthenticator;
use Lens\Bundle\LensSsoBundle\SsoToken;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Bundle\SecurityBundle\Security;

return static function (ContainerConfigurator $container): void {
    $container->services()
        ->set(SsoToken::class)
        ->args([
            service(Security::class),
            service(CacheItemPoolInterface::class),
            abstract_arg('issuer'),
            abstract_arg('private_key_path'),
            abstract_arg('targets'),
        ])

        ->set(SsoAuthenticator::class)
        ->args([
            service(SsoToken::class),
        ]);
};
