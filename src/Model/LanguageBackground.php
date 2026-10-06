<?php

declare(strict_types=1);

// SPDX-License-Identifier: AGPL-3.0-or-later

namespace Gecka\SpamFilter\Model;

/**
 * One background table per language, and the choice of which one a text
 * belongs to.
 *
 * A single table mixing languages understates every word of a monolingual
 * text by the share of its language in the mix, which makes the whole text
 * look unusual. Keeping one table per language and picking the one under
 * which the text is most likely removes that bias; the pick doubles as a
 * language detector.
 *
 * @author Laurent Dinclaux <laurent@gecka.nc>
 * @copyright Gecka <contact@gecka.nc>
 * @license AGPL-3.0-or-later
 */
final class LanguageBackground
{
    /** @var array<string, CountTable> */
    private readonly array $tables;

    /**
     * @param array<string, CountTable> $tables Keyed by language code
     * @param float $alpha Pseudo-count per slot as a share of each table's mean count, as in Estimator
     */
    public function __construct(array $tables, private readonly float $alpha = 0.2)
    {
        if ($tables === []) {
            throw new \InvalidArgumentException('At least one background table is needed');
        }
        $this->tables = $tables;
    }

    /**
     * @return array<string, CountTable>
     */
    public function tables(): array
    {
        return $this->tables;
    }

    /**
     * The language whose table makes the text most likely.
     *
     * @param array<int, int> $hashed Feature hash => count
     */
    public function detect(array $hashed): string
    {
        $best = null;
        $bestScore = -INF;

        foreach ($this->tables as $language => $table) {
            $total = (float) $table->total();
            $score = 0.0;
            foreach ($hashed as $hash => $count) {
                $score += $count * log(Estimator::smoothed((float) $table->get($hash), $total, $table->size, $this->alpha));
            }
            if ($score > $bestScore) {
                $bestScore = $score;
                $best = $language;
            }
        }

        assert($best !== null);

        return $best;
    }

    /**
     * @param array<int, int> $hashed Feature hash => count
     */
    public function select(array $hashed): CountTable
    {
        return $this->tables[$this->detect($hashed)];
    }
}
