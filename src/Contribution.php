<?php

declare(strict_types=1);

// SPDX-License-Identifier: AGPL-3.0-or-later

namespace Gecka\SpamFilter;

/**
 * One feature's share of a verdict, for explanations.
 *
 * @author Laurent Dinclaux <laurent@gecka.nc>
 * @copyright Gecka <contact@gecka.nc>
 * @license AGPL-3.0-or-later
 */
final readonly class Contribution
{
    /**
     * @param float $weight What the count weighs in the verdict: the count itself, or 1 + ln(count) when repetitions are damped
     */
    public function __construct(
        public string $feature,
        public int $count,
        public float $logRatio,
        public float $weight,
    ) {}

    /**
     * The feature's share of Score::logOdds; shares of features hashed to
     * the same slot overlap.
     */
    public function total(): float
    {
        return $this->weight * $this->logRatio;
    }
}
