<?php

declare(strict_types=1);

// SPDX-License-Identifier: AGPL-3.0-or-later

namespace Gecka\SpamFilter\Testing;

use Gecka\SpamFilter\Generation;
use Gecka\SpamFilter\Label;
use Gecka\SpamFilter\Model\ClassCounts;
use Gecka\SpamFilter\Storage\Storage;

/**
 * Checks that a Storage implementation behaves as the filter expects.
 *
 * Framework-agnostic: call verify() from any test and it throws a
 * StorageContractViolation naming the first rule broken. The factory must
 * return a fresh, empty, installed storage for the requested feature space
 * each time it is called.
 *
 *   StorageContract::verify(fn (int $bits) => $this->makeStorage($bits));
 *
 * @author Laurent Dinclaux <laurent@gecka.nc>
 * @copyright Gecka <contact@gecka.nc>
 * @license AGPL-3.0-or-later
 */
final class StorageContract
{
    /**
     * @param callable(int): Storage $factory
     */
    public static function verify(callable $factory, int $bits = 10): void
    {
        self::startsEmpty($factory($bits), $bits);
        self::accumulatesDeltas($factory($bits));
        self::clampsAtZero($factory($bits));
        self::recoversAfterClamping($factory($bits));
        self::foldsHashes($factory($bits), $bits);
        self::matchesInMemoryLayer($factory($bits), $bits);
        self::bumpsVersion($factory($bits));
        self::keepsGenerationsApart($factory($bits));
        self::rotatesGenerations($factory($bits), $bits);
        self::countsLearnedTexts($factory($bits));
        self::hasAStableIdentity($factory($bits), $factory($bits));
    }

    /**
     * A fresh storage reports its feature space and holds nothing.
     */
    private static function startsEmpty(Storage $storage, int $bits): void
    {
        $counts = $storage->load();
        self::check($counts->bits === $bits, "load() must report the feature space it was installed with ($bits bits)");
        self::check($counts->total(Label::Spam) === 0 && $counts->total(Label::Ham) === 0, 'a fresh storage must hold no counts');
        self::check($counts->texts(Label::Spam) === 0 && $counts->texts(Label::Ham) === 0, 'a fresh storage must hold no texts');

        $tally = $storage->tally();
        self::check($tally->generation === 0, 'a fresh storage must be at generation 0');
        self::check($tally->learned(Label::Spam) === 0 && $tally->learned(Label::Ham) === 0, 'a fresh storage must have learned no text');
    }

    /**
     * apply() adds to counters and text counts, keeps the classes apart and subtracts with a negative sign.
     */
    private static function accumulatesDeltas(Storage $storage): void
    {
        $storage->apply([1 => 2, 5 => 1], Label::Spam, 1);
        $storage->apply([1 => 3], Label::Spam, 1);
        $storage->apply([1 => 1, 7 => 4], Label::Ham, 1);

        $counts = $storage->load();
        self::check($counts->count(Label::Spam, 1) === 5, 'apply() must add to an existing counter, not replace it');
        self::check($counts->count(Label::Spam, 5) === 1, 'apply() must create a counter for a new feature');
        self::check($counts->count(Label::Ham, 1) === 1 && $counts->count(Label::Spam, 1) === 5, 'the two classes must be kept apart');
        self::check($counts->count(Label::Ham, 7) === 4, 'apply() must store the full count of a feature');
        self::check($counts->texts(Label::Spam) === 2 && $counts->texts(Label::Ham) === 1, 'each apply() with sign 1 counts one text');

        $storage->apply([1 => 3], Label::Spam, -1);
        $counts = $storage->load();
        self::check($counts->count(Label::Spam, 1) === 2, 'apply() with sign -1 must subtract');
        self::check($counts->texts(Label::Spam) === 1, 'apply() with sign -1 counts one text less');
    }

    /**
     * Counters and text counts never go below zero.
     */
    private static function clampsAtZero(Storage $storage): void
    {
        $storage->apply([1 => 2], Label::Ham, 1);
        $storage->apply([1 => 10, 2 => 5], Label::Ham, -1);

        $counts = $storage->load();
        self::check($counts->count(Label::Ham, 1) === 0, 'a counter must not go below zero');
        self::check($counts->count(Label::Ham, 2) === 0, 'unlearning an unknown feature must leave it at zero');
        self::check($counts->texts(Label::Ham) === 0, 'the text counter must not go below zero');
    }

    /**
     * A clamped counter holds zero, not a negative number the next addition would reveal.
     */
    private static function recoversAfterClamping(Storage $storage): void
    {
        // A clamp that stores a negative number instead of zero shows up only
        // on the next addition, so the sequence is what has to be checked
        $storage->apply([5 => 3], Label::Spam, -1);
        $storage->apply([5 => 3], Label::Spam, 1);
        self::check($storage->load()->count(Label::Spam, 5) === 3, 'learning after unlearning an unknown feature must leave exactly the learned count');
    }

    /**
     * Hashes beyond the feature space fold onto their slot, as ClassCounts folds them.
     */
    private static function foldsHashes(Storage $storage, int $bits): void
    {
        $size = 1 << $bits;
        $storage->apply([7 => 1, 7 + $size => 2, 7 + 3 * $size => 4], Label::Ham, 1);

        $counts = $storage->load();
        self::check($counts->count(Label::Ham, 7) === 7, 'hashes beyond the feature space must fold onto their slot and add up');
        self::check($counts->count(Label::Ham, 7 + $size) === 7, 'a folded hash must read back from its slot');
    }

    /**
     * identity() is non-empty, constant, and differs between two installations.
     */
    private static function hasAStableIdentity(Storage $a, Storage $b): void
    {
        self::check($a->identity() !== '', 'identity() must not be empty');
        self::check($a->identity() === $a->identity(), 'identity() must not change between calls');
        self::check($a->identity() !== $b->identity(), 'two separately installed storages must have different identities');
    }

    /**
     * A learn/unlearn sequence yields the same bytes from the storage as from ClassCounts.
     */
    private static function matchesInMemoryLayer(Storage $storage, int $bits): void
    {
        $memory = new ClassCounts($bits);
        $steps = [[[3 => 2, 9 => 1], Label::Spam], [[3 => 1, 4 => 6], Label::Ham], [[9 => 1], Label::Spam], [[3 => 1], Label::Ham]];

        foreach ($steps as [$hashed, $label]) {
            $storage->apply($hashed, $label, 1);
            $memory->learn($hashed, $label);
        }
        $storage->apply([3 => 1], Label::Ham, -1);
        $memory->unlearn([3 => 1], Label::Ham);

        self::check(
            $storage->load()->toBinary(false) === $memory->toBinary(false),
            'load() must rebuild exactly what ClassCounts holds after the same learn/unlearn sequence',
        );
    }

    /**
     * version() moves after every apply(), whatever the sign and the generation.
     */
    private static function bumpsVersion(Storage $storage): void
    {
        $before = $storage->version();
        $storage->apply([1 => 1], Label::Spam, 1);
        $after = $storage->version();
        self::check($after !== $before, 'version() must change after apply()');

        $storage->apply([1 => 1], Label::Spam, -1);
        self::check($storage->version() !== $after, 'version() must change after apply() with sign -1 too');

        $after = $storage->version();
        $storage->apply([1 => 1], Label::Spam, 1, Generation::Archive);
        self::check($storage->version() !== $after, 'version() must change after apply() to the archive too');
    }

    /**
     * The archive takes its own deltas and clamps on its own; load() adds both generations.
     */
    private static function keepsGenerationsApart(Storage $storage): void
    {
        $storage->apply([1 => 4], Label::Spam, 1);
        $storage->apply([1 => 6, 2 => 1], Label::Spam, 1, Generation::Archive);

        $counts = $storage->load();
        self::check($counts->count(Label::Spam, 1) === 10, 'load() must add the recent and the archived counters');
        self::check($counts->texts(Label::Spam) === 2, 'load() must add the recent and the archived text counts');
        self::check($storage->tally()->recent(Label::Spam) === 1, 'a text learned into the archive must not count as recent');

        $storage->apply([1 => 9], Label::Spam, -1, Generation::Archive);
        self::check($storage->load()->count(Label::Spam, 1) === 4, 'each generation must clamp at zero on its own, leaving the other untouched');
    }

    /**
     * rotate() halves the archive, rounding down, adds the recent counters to
     * it, empties them, and moves the generation and the version.
     */
    private static function rotatesGenerations(Storage $storage, int $bits): void
    {
        $recent = new ClassCounts($bits);
        $archive = new ClassCounts($bits);
        $steps = [
            [[1 => 4], Label::Spam, Generation::Recent],
            [[3 => 1], Label::Ham, Generation::Recent],
            [[1 => 6, 2 => 1], Label::Spam, Generation::Archive],
            [[4 => 3], Label::Ham, Generation::Archive],
            [[4 => 2], Label::Ham, Generation::Archive],
        ];
        $generation = $storage->tally()->generation;
        foreach ($steps as [$hashed, $label, $target]) {
            $written = $storage->apply($hashed, $label, 1, $target);
            self::check($written === $generation, 'apply() must return the generation number it wrote under, whatever the target generation');
            ($target === Generation::Recent ? $recent : $archive)->learn($hashed, $label);
        }
        $before = $storage->version();

        $storage->rotate();
        $archive->halve();

        $counts = $storage->load();
        self::check($counts->count(Label::Spam, 1) === 7, 'rotate() must halve the archive and add the recent counters to it');
        self::check($counts->count(Label::Ham, 4) === 2, 'rotate() must halve the archive rounding down');
        self::check($counts->count(Label::Spam, 2) === 0, 'rotate() must bring an archived count of one to zero');
        self::check($counts->texts(Label::Spam) === 1 && $counts->texts(Label::Ham) === 2, 'rotate() must halve the archived text counts, rounding down, and add the recent ones');
        self::check($counts->toBinary(false) === $archive->plus($recent)->toBinary(false), 'load() after rotate() must match the halved archive plus the recent layer');

        $tally = $storage->tally();
        self::check($tally->generation === $generation + 1, 'rotate() must move the generation by one');
        self::check($tally->recent(Label::Spam) === 0 && $tally->recent(Label::Ham) === 0, 'rotate() must empty the recent generation');
        self::check($storage->version() !== $before, 'version() must change after rotate()');

        self::check($storage->apply([1 => 1], Label::Spam, 1) === $generation + 1, 'apply() after rotate() must return the new generation number');
        self::check($storage->load()->count(Label::Spam, 1) === 8, 'apply() after rotate() must add to the recent generation');

        $storage->apply([1 => 7], Label::Spam, -1, Generation::Archive);
        self::check($storage->load()->count(Label::Spam, 1) === 1, 'the archive must give back what the rotation moved into it, and only that');
    }

    /**
     * The texts learned in all follow the sign of apply() in both
     * generations, stop at zero, and no rotation halves them.
     */
    private static function countsLearnedTexts(Storage $storage): void
    {
        $storage->apply([1 => 1], Label::Spam, 1);
        $storage->apply([2 => 1], Label::Spam, 1, Generation::Archive);
        $storage->apply([3 => 1], Label::Ham, 1);
        $storage->rotate();
        $storage->rotate();

        $tally = $storage->tally();
        self::check($tally->learned(Label::Spam) === 2 && $tally->learned(Label::Ham) === 1, 'rotate() must leave the texts learned in all untouched');

        $storage->apply([3 => 1], Label::Ham, -1, Generation::Archive);
        $storage->apply([3 => 1], Label::Ham, -1);
        self::check($storage->tally()->learned(Label::Ham) === 0, 'the texts learned in all must follow the sign of apply() and stop at zero');
    }

    /**
     * Throws a StorageContractViolation naming $rule when $holds is false.
     */
    private static function check(bool $holds, string $rule): void
    {
        if (! $holds) {
            throw new StorageContractViolation($rule);
        }
    }
}
