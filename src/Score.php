<?php

declare(strict_types=1);

// SPDX-License-Identifier: AGPL-3.0-or-later

namespace Gecka\SpamFilter;

/**
 * The verdict on one text.
 *
 * logOdds sums the evidence of every feature occurrence: 0 means nothing
 * known, positive leans spam, negative leans legitimate. evidence() divides
 * it by the square root of the number of occurrences, which is the figure to
 * put a threshold on: it neither favours long texts (as the raw sum does)
 * nor discards how much evidence there is (as the mean does). probability()
 * squashes it into [0, 1] for callers that want a probability.
 *
 * @author Laurent Dinclaux <laurent@gecka.nc>
 * @copyright Gecka <contact@gecka.nc>
 * @license AGPL-3.0-or-later
 */
final readonly class Score
{
    /**
     * @param float $logOdds Summed evidence of every feature occurrence
     * @param int $occurrences Number of feature occurrences in the text
     */
    public function __construct(
        public float $logOdds,
        public int $occurrences,
    ) {}

    /**
     * Summed evidence over the number of occurrences, zero for an empty text.
     */
    public function meanLogOdds(): float
    {
        return $this->occurrences > 0 ? $this->logOdds / $this->occurrences : 0.0;
    }

    /**
     * Summed evidence over the square root of the text length. Around 0 the
     * filter does not know; past 0.5 or 1 it leans clearly; past 2 it is
     * sure. Pick the exact thresholds from your own corrections.
     */
    public function evidence(): float
    {
        return $this->occurrences > 0 ? $this->logOdds / sqrt($this->occurrences) : 0.0;
    }

    /**
     * evidence() squashed into [0, 1]: 0.5 means nothing known.
     */
    public function probability(): float
    {
        return 1.0 / (1.0 + exp(-$this->evidence()));
    }
}
