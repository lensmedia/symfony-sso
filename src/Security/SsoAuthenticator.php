<?php

declare(strict_types=1);

namespace Lens\Bundle\LensSsoBundle\Security;

use Lens\Bundle\LensSsoBundle\SsoToken;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\RememberMeBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Throwable;

class SsoAuthenticator extends AbstractAuthenticator
{
    public const string TOKEN_PARAMETER = 'sso';

    public function __construct(
        private readonly SsoToken $ssoToken,
    ) {
    }

    public function supports(Request $request): ?bool
    {
        return $request->query->has(self::TOKEN_PARAMETER);
    }

    public function authenticate(Request $request): Passport
    {
        $token = $request->query->get(self::TOKEN_PARAMETER);

        try {
            $payload = $this->ssoToken->validate($token);
        } catch (Throwable $exception) {
            throw new CustomUserMessageAuthenticationException(
                'SSO authentication failed: '.$exception->getMessage(),
                previous: $exception,
            );
        }

        $request->attributes->set('_lens_sso_target_path', $payload->targetPath);

        return new SelfValidatingPassport(new UserBadge($payload->username), [
            new RememberMeBadge(),
        ]);
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?RedirectResponse
    {
        $path = $request->attributes->get('_lens_sso_target_path');
        if (null !== $path) {
            return new RedirectResponse($path);
        }

        return $this->getSuccessFallbackResponse($request, $token, $firewallName);
    }

    /**
     * "abstract" methods that can be used to override the fallback of the default methods without having to write the full method.
     *
     * This method can be ignored when going with the default behavior of redirecting to the target path if provided,
     * but it can be useful if you want to have a custom response on success without having to copy the full method.
     */
    public function getSuccessFallbackResponse(Request $request, TokenInterface $token, string $firewallName): ?RedirectResponse
    {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        return $this->getFailureFallbackResponse($request, $exception);
    }

    /**
     * "abstract" methods that can be used to override the fallback of the default methods without having to copy the
     * full method. For failure, it is the same though for now, but it is separated for better readability and future
     * flexibility if needed.
     *
     * This method can be ignored when going with the default behavior of returning null and letting the exception
     * propagate, but it can be useful if you want to have a custom response.
     */
    public function getFailureFallbackResponse(Request $request, AuthenticationException $exception): ?RedirectResponse
    {
        return null;
    }
}
