<?php

declare(strict_types=1);

use FancyPasskeys\CeremonyType;
use FancyPasskeys\ChallengeRecord;
use FancyPasskeys\Support\InMemoryChallengeStore;
use FancyPasskeys\Tests\Support\TestClock;

it('deletes the record as it reads it', function () {
    $clock = new TestClock();
    $store = new InMemoryChallengeStore($clock->now(...));

    $store->put('state-1', new ChallengeRecord(
        'Y2hhbGxlbmdl',
        CeremonyType::Registration,
        'aGFuZGxl',
        $clock->now() + 300_000,
    ));

    expect($store->pull('state-1'))->not->toBeNull();

    // The second pull is the one that matters: this is what turns a replayed
    // response into "no such challenge" regardless of how valid its signature
    // is. A store that reads without deleting makes every captured response
    // reusable forever, and nothing anywhere reports it.
    expect($store->pull('state-1'))->toBeNull();
});

it('returns null for an unknown handle', function () {
    $store = new InMemoryChallengeStore();

    expect($store->pull('never-issued'))->toBeNull();
});

it('treats an expired record as absent and still deletes it', function () {
    $clock = new TestClock();
    $store = new InMemoryChallengeStore($clock->now(...));

    $store->put('state-1', new ChallengeRecord(
        'Y2hhbGxlbmdl',
        CeremonyType::Authentication,
        null,
        $clock->now() + 300_000,
    ));

    $clock->advanceSeconds(301);

    expect($store->pull('state-1'))->toBeNull();

    // Deleted, not merely hidden — an expired record that lingers is a record
    // that a clock skew, a replica lag, or a manual TTL bump can resurrect.
    expect($store->count())->toBe(0);
});

it('expires exactly at the deadline, not a millisecond later', function () {
    $clock = new TestClock();
    $store = new InMemoryChallengeStore($clock->now(...));
    $expiresAt = $clock->now() + 1000;

    $store->put('state-1', new ChallengeRecord('Y2hhbGxlbmdl', CeremonyType::Registration, null, $expiresAt));
    $clock->advanceSeconds(1);

    expect($store->pull('state-1'))->toBeNull();
});
