<?php

declare(strict_types=1);

namespace FancyPasskeys\Laravel\Http;

use FancyPasskeys\Laravel\Events\PasskeyRegistered;
use FancyPasskeys\Laravel\PasskeyManager;
use FancyPasskeys\PasskeyException;
use FancyPasskeys\PasskeyUser;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use RuntimeException;

/**
 * Enrollment. Both endpoints require an authenticated user — v1 has no
 * passkey-only signup (see the README's "Not in scope").
 */
final class PasskeyRegistrationController
{
    use RespondsWithPasskeyErrors;

    public function __construct(private readonly PasskeyManager $passkeys)
    {
    }

    public function options(Request $request): JsonResponse
    {
        $user = $this->user($request);

        // `user.name` and `user.displayName` are what the account picker shows.
        // Neither participates in verification, so a sensible fallback is
        // better than a hard requirement on a particular column.
        $name = $this->attribute($user, 'email') ?? (string) $user->getAuthIdentifier();
        $displayName = $this->attribute($user, 'name') ?? $name;

        try {
            $result = $this->passkeys->startRegistration(new PasskeyUser(
                $this->handleFor($user),
                $name,
                $displayName,
            ));
        } catch (PasskeyException $e) {
            return $this->failed($e);
        }

        return $this->ok($result);
    }

    public function store(Request $request): JsonResponse
    {
        $user = $this->user($request);

        $validated = $request->validate([
            'state' => ['required', 'string'],
            'name' => ['nullable', 'string', 'max:255'],
            'response' => ['required', 'array'],
        ]);

        try {
            $result = $this->passkeys->finishRegistration(
                $validated['state'],
                $validated['response'],
                $validated['name'] ?? null,
            );
        } catch (PasskeyException $e) {
            return $this->failed($e);
        }

        PasskeyRegistered::dispatch($user, $result['credential']);

        return $this->ok(['credential' => $result['summary']], 201);
    }

    private function user(Request $request): Authenticatable
    {
        $user = $request->user($this->passkeys->guard());

        if ($user === null) {
            // The route group is behind auth middleware, so this is a wiring
            // bug rather than a client error.
            throw new RuntimeException('Passkey enrollment requires an authenticated user.');
        }

        return $user;
    }

    private function handleFor(Authenticatable $user): string
    {
        if (! method_exists($user, 'passkeyUserHandle')) {
            throw new RuntimeException(sprintf(
                'Add the FancyPasskeys\Laravel\Concerns\HasPasskeys trait to %s.',
                $user::class,
            ));
        }

        return (string) $user->passkeyUserHandle();
    }

    private function attribute(Authenticatable $user, string $key): ?string
    {
        $value = data_get($user, $key);

        return is_string($value) && $value !== '' ? $value : null;
    }
}
