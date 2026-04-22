<?php

declare(strict_types=1);

use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;

return static function (DefinitionConfigurator $definition): void {
    $definition->rootNode()
        ->children()
            ->scalarNode('issuer')
                ->info('Local issuer name, note that any validating remote needs to have an sso target with this name too.')
            ->end()
            ->scalarNode('private_key_path')
                ->info('Local issuer private key, used to sign the SSO tokens.')
            ->end()
            ->arrayNode('targets')
                ->useAttributeAsKey('name')
                ->arrayPrototype()
                ->children()
                    ->scalarNode('base_url')->end()
                    ->scalarNode('public_key_path')->end()
                ->end()
            ->end()
        ->end()
    ->end();
};
