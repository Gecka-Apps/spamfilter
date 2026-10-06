<?php

declare(strict_types=1);

// SPDX-License-Identifier: AGPL-3.0-or-later

namespace Gecka\SpamFilter\Tokenizer;

/**
 * Projects readable features onto 32-bit integers with xxh3, so the model is
 * made of fixed-size tables whatever the vocabulary, and stores no word in
 * clear.
 *
 * Each count table folds the integer into its own size with a mask, so
 * tables of different sizes (a small site layer, a large background) work
 * from the same hash.
 *
 * @author Laurent Dinclaux <laurent@gecka.nc>
 * @copyright Gecka <contact@gecka.nc>
 * @license AGPL-3.0-or-later
 */
final class FeatureHasher
{
    public const BITS = 32;

    /**
     * Bumped whenever the hash or the feature extraction changes in a way
     * that moves features to other slots. Stored in every model file and
     * storage, so a stale model is refused instead of silently misread.
     */
    public const VERSION = 1;

    /**
     * The xxh3 hash of one feature, folded to 32 bits.
     */
    public function hash(string $feature): int
    {
        /** @var array{1: int} $unpacked */
        $unpacked = unpack('N', hash('xxh3', $feature, true));

        return $unpacked[1];
    }

    /**
     * Hashes a bag of features; features landing on the same value add up.
     *
     * @param array<string, int> $features
     * @return array<int, int> Hash => count
     */
    public function hashAll(array $features): array
    {
        $hashed = [];
        foreach ($features as $feature => $count) {
            $hash = $this->hash((string) $feature);
            $hashed[$hash] = ($hashed[$hash] ?? 0) + $count;
        }

        return $hashed;
    }
}
