<?php

declare(strict_types=1);

// SPDX-License-Identifier: AGPL-3.0-or-later

use Gecka\SpamFilter\Model\CountTable;
use Gecka\SpamFilter\Tokenizer\FeatureHasher;

it('maps every feature onto a 32-bit integer', function (): void {
    $hasher = new FeatureHasher();

    foreach (['w:bonjour', 'c3:_bo', 'host:example.com', ''] as $feature) {
        $hash = $hasher->hash($feature);
        expect($hash)->toBeGreaterThanOrEqual(0)->toBeLessThanOrEqual(0xFFFFFFFF);
    }
});

it('is deterministic', function (): void {
    $hasher = new FeatureHasher();

    expect($hasher->hash('w:bonjour'))->toBe($hasher->hash('w:bonjour'));
    expect($hasher->hash('w:bonjour'))->not->toBe($hasher->hash('w:bonsoir'));
});

it('adds up counts of features with the same hash', function (): void {
    $hasher = new FeatureHasher();

    $hashed = $hasher->hashAll(['w:bonjour' => 2, 'w:bonsoir' => 3]);

    expect($hashed)->toBe([
        $hasher->hash('w:bonjour') => 2,
        $hasher->hash('w:bonsoir') => 3,
    ]);
});

it('lets tables of different sizes share one hash', function (): void {
    $hasher = new FeatureHasher();
    $small = new CountTable(256);
    $large = new CountTable(1 << 16);

    $hash = $hasher->hash('w:bonjour');
    $small->add($hash, 1);
    $large->add($hash, 1);

    expect($small->get($hash))->toBe(1);
    expect($large->get($hash))->toBe(1);
    // The small table folds the hash: another hash with the same low 8 bits lands on the same slot
    expect($small->get($hash + 256))->toBe(1);
    expect($large->get($hash + 256))->toBe(0);
});
