<?php

declare(strict_types=1);

namespace FancyPasskeys\Laravel\Http;

use FancyPasskeys\Laravel\Events\PasskeyAuthenticated;
use FancyPasskeys\Laravel\PasskeyManager;
use FancyPasskeys\PasskeyException;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use RuntimeException;

/**
 * Passkey login — a parallel path to the same session Fortify produces.
 *
 * Password login, registration, reset and 2FA are untouched. Nothing here
 * modifies or re-registers a Fortify route.
 */
final class PasskeyLoginController
{
    use RespondsWithPasskeyErrors;

    public function __construct(
        private readonly PasskeyManager $passkeys,
        private readonly AuthFactory $auth,
    ) {
    }

    public function options(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'email' => ['nullable', 'string', 'max:255'],
        ]);

        $email = $validated['email'] ?? null;

        /*
         * An unknown email returns a well-formed payload with an empty
         * allowCredentials — never a 404. A 404 here is a free user-enumeration
         * endpoint, and it is one of the most common ways a passkey rollout
         * makes an app *less* private than it was with passwords.
         *
         * A known user with no passkeys yet produces the identical response, so
         * the two are indistinguishable by shape. The timing difference is not
         * fully closed (a real lookup happens either way) and the README says
         * so rather than implying a guarantee we have not measured.
         */
        $userHandle = $email === null ? null : $this->handleForEmail($email);

        try {
            $result = $this->passkeys->startAuthentication($userHandle);
        } catch (PasskeyException $e) {
            return $this->failed($e);
        }

        return $this->ok($result);
    }

    public function store(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'state' => ['required', 'string'],
            'response' => ['required', 'array'],
        ]);

        try {
            $result = $this->passkeys->finishAuthentication($validated['state'], $validated['response']);
        } catch (PasskeyException $e) {
            return $this->failed($e);
        }

        $user = $this->userForHandle($result['userHandle']);

        if ($user === null) {
            // The credential verified but its account is gone. Same generic
            // failure as a bad signature — the client learns nothing.
            return $this->failed(PasskeyException::unknownCredential());
        }

        $guard = $this->auth->guard($this->passkeys->guard());

        if (! $guard instanceof StatefulGuard) {
            throw new RuntimeException(sprintf(
                'The "%s" guard is not stateful, so it cannot establish a passkey session.',
                $this->passkeys->guard(),
            ));
        }

        /*
         * SessionGuard::login() dispatches Illuminate\Auth\Events\Login itself,
         * which is exactly how Fortify produces it — so anything listening
         * (fun-lab, heuristics, audit) cannot tell a passkey session from a
         * password one. We deliberately do NOT dispatch Login a second time:
         * double-firing would double-count every one of those listeners.
         */
        $guard->login($user);

        $request->session()->regenerate();

        PasskeyAuthenticated::dispatch($user, $result['credential']);

        return $this->ok([
            'user' => [
                'id' => $user->getAuthIdentifier(),
                'name' => data_get($user, 'name'),
                'email' => data_get($user, 'email'),
            ],
            'credential' => $result['summary'],
        ]);
    }

    private function handleForEmail(string $email): ?string
    {
        $user = $this->userQuery()->where('email', $email)->first();

        $handle = $user === null ? null : data_get($user, 'passkey_user_handle');

        return is_string($handle) && $handle !== '' ? $handle : null;
    }

    private function userForHandle(string $handle): ?Authenticatable
    {
        $user = $this->userQuery()->where('passkey_user_handle', $handle)->first();

        return $user instanceof Authenticatable ? $user : null;
    }

    /** @return \Illuminate\Database\Eloquent\Builder<Model> */
    private function userQuery()
    {
        /** @var class-string<Model> $model */
        $model = config('passkeys.users.model') ?? config('auth.providers.users.model', 'App\\Models\\User');

        return $model::query();
    }
}
