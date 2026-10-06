<?php

declare(strict_types=1);

// SPDX-License-Identifier: AGPL-3.0-or-later

namespace Gecka\SpamFilter;

use Gecka\SpamFilter\Model\ClassCounts;
use Gecka\SpamFilter\Model\CountTable;
use Gecka\SpamFilter\Model\Estimator;
use Gecka\SpamFilter\Model\LanguageBackground;
use Gecka\SpamFilter\Storage\Storage;
use Gecka\SpamFilter\Tokenizer\FeatureExtractor;
use Gecka\SpamFilter\Tokenizer\FeatureHasher;

/**
 * The filter: scores texts, learns from corrections, explains itself.
 *
 * The site layer is the only one that changes: learn() and unlearn() update
 * the in-memory snapshot and, when a storage is given, the database behind
 * it, and rotate() ages it. The optional pre-trained layer is read-only, and
 * the background tells a common word from a rare one before the site has
 * learned any legitimate text; with one table per language, the table is
 * chosen for each text.
 *
 * @author Laurent Dinclaux <laurent@gecka.nc>
 * @copyright Gecka <contact@gecka.nc>
 * @license AGPL-3.0-or-later
 */
final class SpamFilter
{
    private readonly FeatureHasher $hasher;

    private readonly CountTable|LanguageBackground|null $background;

    private ClassCounts $site;

    /**
     * @param bool $logCounts Weigh a repeated feature as 1 + ln(count) instead of count
     */
    public function __construct(
        ClassCounts $site,
        private readonly ?ClassCounts $pretrained = null,
        CountTable|LanguageBackground|null $background = null,
        private readonly FeatureExtractor $extractor = new FeatureExtractor(),
        private readonly float $pretrainedWeight = 0.5,
        private readonly float $backgroundWeight = 10.0,
        private readonly float $alpha = 0.2,
        private readonly bool $logCounts = false,
        private readonly ?Storage $storage = null,
    ) {
        $this->hasher = new FeatureHasher();
        $this->background = $background;
        $this->site = $site;
    }

    /**
     * Scores a text against the site layer, the pre-trained layer and the background.
     */
    public function classify(string $text): Score
    {
        $hashed = $this->hasher->hashAll($this->extractor->extract($text));
        $estimator = $this->estimator($hashed);

        $logOdds = 0.0;
        $occurrences = 0;
        foreach ($hashed as $index => $count) {
            $logOdds += $this->weight($count) * $estimator->logRatio($index);
            $occurrences += $count;
        }

        return new Score($logOdds, $occurrences);
    }

    /**
     * Adds a text's features to a class, in the storage first and then in the
     * snapshot, and returns the generation the text now belongs to, the
     * number unlearn() needs later. A text dated before the last rotation can
     * go straight to the archive, where it weighs what it would had it been
     * learned in time; it then belongs to the previous generation. Without a
     * storage there is one generation, 0.
     */
    public function learn(string $text, Label $label, Generation $generation = Generation::Recent): int
    {
        $hashed = $this->hasher->hashAll($this->extractor->extract($text));
        $current = $this->storage?->apply($hashed, $label, 1, $generation) ?? 0;
        $this->site->learn($hashed, $label);

        return $generation === Generation::Archive ? $current - 1 : $current;
    }

    /**
     * Takes back a learn() of the same text and class. $learnedIn is what
     * learn() returned, which the caller keeps with the text: a guess would
     * subtract from a generation that does not hold the text and erode the
     * counts of other texts instead. A text of the current generation comes
     * off the recent counters, one of the previous generation off the
     * archive, where it still has its full weight. An older one was halved
     * since and cannot be taken back exactly: nothing changes and the answer
     * is false. A generation that does not exist yet is refused.
     */
    public function unlearn(string $text, Label $label, int $learnedIn): bool
    {
        $current = $this->generation();

        if ($learnedIn > $current) {
            throw new \InvalidArgumentException("No text was learned in generation $learnedIn yet, the storage is at $current");
        }
        if ($learnedIn < $current - 1) {
            return false;
        }

        $hashed = $this->hasher->hashAll($this->extractor->extract($text));
        $this->storage?->apply($hashed, $label, -1, $learnedIn < $current ? Generation::Archive : Generation::Recent);
        $this->site->unlearn($hashed, $label);

        return true;
    }

    /**
     * Ages the site layer: the archive halves, the recent counters join it,
     * and the snapshot is reloaded from the storage. Counters only grow
     * otherwise, and a campaign learned a thousand times two years ago would
     * still outweigh what arrives today. A rotation every few months, or
     * once the recent generation holds a few thousand texts of a class,
     * keeps recent corrections in charge without ever halving them in their
     * first period.
     */
    public function rotate(): void
    {
        if ($this->storage === null) {
            throw new \LogicException('Rotating needs a storage: the snapshot alone does not know which counts are recent');
        }

        $this->storage->rotate();
        $this->site = $this->storage->load();
    }

    /**
     * Rotations the storage went through, 0 without a storage.
     */
    public function generation(): int
    {
        return $this->storage?->tally()->generation ?? 0;
    }

    /**
     * Every feature of the text with its weight in the verdict, strongest first.
     * Features hashed to the same slot share one ratio and are listed separately.
     *
     * @return list<Contribution>
     */
    public function explain(string $text): array
    {
        $features = $this->extractor->extract($text);
        $hashes = [];
        foreach ($features as $feature => $count) {
            $hashes[$feature] = $this->hasher->hash((string) $feature);
        }
        $hashed = [];
        foreach ($hashes as $feature => $hash) {
            $hashed[$hash] = ($hashed[$hash] ?? 0) + $features[$feature];
        }
        $estimator = $this->estimator($hashed);

        $contributions = [];
        foreach ($features as $feature => $count) {
            $contributions[] = new Contribution((string) $feature, $count, $estimator->logRatio($hashes[$feature]), $this->weight($count));
        }

        usort($contributions, static fn(Contribution $a, Contribution $b): int => abs($b->total()) <=> abs($a->total()));

        return $contributions;
    }

    /**
     * The language the background would file the text under, or null without
     * a per-language background.
     */
    public function language(string $text): ?string
    {
        if (! $this->background instanceof LanguageBackground) {
            return null;
        }

        return $this->background->detect($this->hasher->hashAll($this->extractor->extract($text)));
    }

    /**
     * @param array<int, int> $hashed
     */
    private function estimator(array $hashed): Estimator
    {
        $background = $this->background instanceof LanguageBackground
            ? $this->background->select($hashed)
            : $this->background;

        return new Estimator($this->site, $this->pretrained, $background, $this->pretrainedWeight, $this->backgroundWeight, $this->alpha);
    }

    /**
     * How much a feature repeated $count times in one text counts.
     */
    private function weight(int $count): float
    {
        return $this->logCounts ? 1.0 + log($count) : (float) $count;
    }
}
