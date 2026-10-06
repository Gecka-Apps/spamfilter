<?php

declare(strict_types=1);

// SPDX-License-Identifier: AGPL-3.0-or-later

namespace Gecka\SpamFilter\Storage;

use Gecka\SpamFilter\Generation;
use Gecka\SpamFilter\Label;
use Gecka\SpamFilter\Model\ClassCounts;

/**
 * Durable home of the site layer: the counters live in a database, the
 * filter works on an in-memory snapshot of them.
 *
 * Every counter exists twice, in a recent generation and in an archive. The
 * snapshot is their sum. A rotation halves the archive, rounding down, adds
 * the recent counters to it and empties the recent generation: what was
 * learned since the last rotation keeps its full weight until the next one,
 * then halves with every rotation after that.
 *
 * @author Laurent Dinclaux <laurent@gecka.nc>
 * @copyright Gecka <contact@gecka.nc>
 * @license AGPL-3.0-or-later
 */
interface Storage
{
    /**
     * Builds a snapshot of every counter, both generations added together.
     */
    public function load(): ClassCounts;

    /**
     * Adds (or, with a negative sign, removes) one text's features to a
     * class in one generation, atomically. Concurrent calls must not lose
     * updates. Hashes are folded into the feature space the storage was
     * installed with, exactly as ClassCounts folds them, and each generation
     * clamps at zero on its own. The count of texts learned in all moves
     * with the sign too.
     *
     * Returns the generation number the write happened under, read in the
     * same atomic unit as the write so that no rotation can fall between
     * the two: it is what the filter hands back to the caller for a later
     * unlearn().
     *
     * @param array<int, int> $hashed Feature hash => count
     */
    public function apply(array $hashed, Label $label, int $sign, Generation $generation = Generation::Recent): int;

    /**
     * Halves every archived counter and archived text count, rounding down,
     * adds the recent ones to them, empties the recent generation, and moves
     * both the generation and the version.
     */
    public function rotate(): void;

    /**
     * The generation number, the texts of the recent generation and the
     * texts learned in all, read from the storage every time.
     */
    public function tally(): Tally;

    /**
     * A number that changes with every apply() and rotate(), so a cached
     * snapshot knows when it is stale.
     */
    public function version(): int;

    /**
     * A string that tells this storage from any other one a cache could be
     * shared with: two sites on one server must never read each other's
     * snapshot. It must not change for the life of the storage.
     */
    public function identity(): string;
}
