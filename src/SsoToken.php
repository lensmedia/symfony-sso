<?php

declare(strict_types=1);

namespace Lens\Bundle\LensSsoBundle;

use DateTimeImmutable;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\SignatureInvalidException;
use Lens\Bundle\LensSsoBundle\Security\SsoAuthenticator;
use LogicException;
use Psr\Cache\CacheItemPoolInterface;
use RuntimeException;
use SensitiveParameter;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use UnexpectedValueException;

final class SsoToken
{
    private const string ALGORITHM = 'RS256';
    private const int TOKEN_TTL = 60;
    private const string CACHE_PREFIX = 'lens_sso_jti_';

    public function __construct(
        private readonly Security $security,
        private readonly CacheItemPoolInterface $cache,
        private readonly ?string $issuer,
        #[SensitiveParameter]
        private readonly ?string $privateKeyPath,
        private readonly array $targets,
    ) {
    }

    /**
     * Creates a redirect response to the SSO target with a newly issued token for the currently authenticated user.
     *
     * This can be used in a custom sso controller action to generate a redirect response for a given audience and
     * incoming request, which may contain an optional target path query parameter and origin to allow returning to
     * a specific url on the issuers side.
     */
    public function createRedirectFromRequest(string $audience, Request $request): RedirectResponse
    {
        if (!$this->security->isGranted('IS_AUTHENTICATED')) {
            throw new AccessDeniedHttpException('User must be authenticated to be able to generate a SSO redirect response.');
        }

        $data = new SsoTokenData(
            username: $this->security->getUser()->getUserIdentifier(),
            targetPath: $request->query->get('path'),
            origin: $request->query->get('origin'),
        );

        $token = $this->create($audience, $data);
        $entryUrl = $this->buildEntryUrl($audience, $token, $request->query->get('path'));

        return new RedirectResponse($entryUrl);
    }

    /**
     * Creates a new SSO token for the given audience and token data, which includes the username of the associated user
     * and optional target path and origin information.
     */
    public function create(string $audience, SsoTokenData $data): string
    {
        if (null === $this->issuer) {
            throw new LogicException('SSO token issuer is required to be configured to create tokens.');
        }

        $issuedAt = time();

        $payload = [
            'iss' => $this->issuer,
            'aud' => $audience,
            'sub' => $data->username,
            'iat' => $issuedAt,
            'exp' => $issuedAt + self::TOKEN_TTL,
            'jti' => $this->generateJti(),
        ];

        if (null !== $data->targetPath && '' !== $data->targetPath) {
            $payload['path'] = $data->targetPath;
        }

        if (null !== $data->origin && '' !== $data->origin) {
            $payload['origin'] = $data->origin;
        }

        return JWT::encode($payload, $this->privateKey(), self::ALGORITHM, $this->issuer);
    }

    /**
     * Validates an incoming SSO token and returns the associated token data if valid.
     *
     * @throws ExpiredException when the token has expired
     * @throws BeforeValidException when the token is not yet valid
     * @throws SignatureInvalidException when the token signature is invalid
     * @throws UnexpectedValueException when the token is malformed or has an invalid audience or missing jti
     * @throws RuntimeException when the token has already been used
     * @throws LogicException when the SSO token issuer or target configuration is missing or invalid
     */
    public function validate(string $token): SsoTokenData
    {
        $decoded = JWT::decode($token, $this->publicKeys());

        $payload = (array)$decoded;

        if (($payload['aud'] ?? null) !== $this->issuer) {
            throw new UnexpectedValueException('SSO token audience mismatch.');
        }

        $jti = $payload['jti'] ?? null;
        if (null === $jti) {
            throw new UnexpectedValueException('SSO token missing jti claim.');
        }

        if ($this->isJtiConsumed($jti)) {
            throw new RuntimeException('SSO token has already been used.');
        }

        $this->consumeJti($jti, (int)($payload['exp'] ?? time() + self::TOKEN_TTL));

        return new SsoTokenData($payload['sub'], $payload['path'] ?? null, $payload['origin'] ?? null);
    }

    private function buildEntryUrl(string $audience, string $token, ?string $path = null): string
    {
        $url = rtrim($this->targets[$audience]['base_url'] ?? '', '/');
        if ('' === $url) {
            throw new RuntimeException(sprintf('No SSO target url configured for audience "%s".', $audience));
        }

        $path = ltrim($path ?? '', '/');
        if ('' !== $path) {
            $path = '/'.$path;
        }

        $joiner = str_contains($url.$path, '?') ? '&' : '?';

        return $url.$path.$joiner.SsoAuthenticator::TOKEN_PARAMETER.'='.urlencode($token);
    }

    private function privateKey(): string
    {
        static $key = null;
        if (null === $key) {
            if (null === $this->privateKeyPath || !file_exists($this->privateKeyPath) || !is_readable($this->privateKeyPath)) {
                throw new LogicException('SSO private key path is required to be configured (and file has to be readable) to create tokens.');
            }

            $key = file_get_contents($this->privateKeyPath);
        }

        return $key;
    }

    private function publicKeys(): array
    {
        static $keys = [];
        if (empty($keys)) {
            foreach ($this->targets as $audience => $config) {
                if (!isset($config['public_key_path']) || !file_exists($config['public_key_path']) || !is_readable($config['public_key_path'])) {
                    throw new LogicException(sprintf('SSO token audience "%s" public key path is required to be configured (and file has to be readable) to validate tokens.', $audience));
                }

                $keys[$audience] = new Key(file_get_contents($config['public_key_path']), self::ALGORITHM);
            }
        }

        return $keys;
    }

    private function generateJti(): string
    {
        return bin2hex(random_bytes(16));
    }

    private function isJtiConsumed(string $jti): bool
    {
        return $this->cache->getItem(self::CACHE_PREFIX.$jti)->isHit();
    }

    private function consumeJti(string $jti, int $expiry): void
    {
        $item = $this->cache->getItem(self::CACHE_PREFIX.$jti);
        $item->set(true);
        $item->expiresAt(new DateTimeImmutable('@'.$expiry));
        $this->cache->save($item);
    }
}
