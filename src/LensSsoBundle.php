<?php

namespace Lens\Bundle\LensSsoBundle;

use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;

class LensSsoBundle extends AbstractBundle
{
    private const array DEFAULT_TARGETS = [
        'lens' => [
            'base_url' => 'https://lensmedia.nl',
            'public_key_path' => __DIR__.'/../config/certificates/sso_public_lens.pem',
        ],
        'itheorie' => [
            'base_url' => 'https://itheorie.nl',
            'public_key_path' => __DIR__.'/../config/certificates/sso_public_itheorie.pem',
        ],
        'examencentrum' => [
            'base_url' => 'https://examencentrum.nl',
            'public_key_path' => __DIR__.'/../config/certificates/sso_public_examencentrum.pem',
        ],
    ];

    public function configure(DefinitionConfigurator $definition): void
    {
        $definition->import('../config/definition.php');
    }

    public function loadExtension(array $config, ContainerConfigurator $configurator, ContainerBuilder $container): void
    {
        $configurator->import('../config/services.php');

        $config['targets'] = array_replace_recursive(self::DEFAULT_TARGETS, $config['targets'] ?? []);
        $config = $container->resolveEnvPlaceholders($config, true);

        // Set sso config parameters
        $configurator->services()
            ->get(SsoToken::class)
            ->arg(2, $config['issuer'] ?? null)
            ->arg(3, $config['private_key_path'] ?? null)
            ->arg(4, $config['targets'] ?? []);
    }
}
