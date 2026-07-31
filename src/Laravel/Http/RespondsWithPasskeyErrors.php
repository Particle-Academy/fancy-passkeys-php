<?php

declare(strict_types=1);

namespace FancyPasskeys\Laravel\Http;

use FancyPasskeys\PasskeyException;
use Illuminate\Http\JsonResponse;

/**
 * One error shape, one cache policy, both backends.
 */
trait RespondsWithPasskeyErrors
{
    /** @param array<string, mixed> $payload */
    private function ok(array $payload, int $status = 200): JsonResponse
    {
        // Options payloads carry a live challenge and credential descriptors.
        // Neither belongs in a shared cache, a browser back-forward cache, or a
        // proxy.
        return response()->json($payload, $status)->header('Cache-Control', 'no-store');
    }

    private function failed(PasskeyException $e): JsonResponse
    {
        return response()
            ->json($e->toArray(), $e->httpStatus())
            ->header('Cache-Control', 'no-store');
    }
}
