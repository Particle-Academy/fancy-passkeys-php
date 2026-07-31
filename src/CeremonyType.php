<?php

declare(strict_types=1);

namespace FancyPasskeys;

/**
 * Which ceremony a challenge was issued for.
 *
 * A stored challenge carries its type so a registration challenge cannot be
 * redeemed at the authentication endpoint (or the reverse). Without it, the two
 * endpoints share one pool of live challenges and the ceremony boundary is
 * decorative.
 */
enum CeremonyType: string
{
    case Registration = 'registration';
    case Authentication = 'authentication';
}
