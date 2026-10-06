<?php

declare(strict_types=1);

// SPDX-License-Identifier: AGPL-3.0-or-later

namespace Gecka\SpamFilter\Storage;

use Gecka\SpamFilter\Label;

/**
 * What a storage can tell about its generations: how many rotations it went
 * through, how many texts the recent generation holds, and how many texts
 * were learned in all, a figure no rotation halves.
 *
 * @author Laurent Dinclaux <laurent@gecka.nc>
 * @copyright Gecka <contact@gecka.nc>
 * @license AGPL-3.0-or-later
 */
final class Tally
{
    /**
     * @param int $generation Rotations since install
     */
    public function __construct(
        public readonly int $generation,
        private readonly int $recentSpam,
        private readonly int $recentHam,
        private readonly int $learnedSpam,
        private readonly int $learnedHam,
    ) {}

    /**
     * Texts of the class in the recent generation, the volume the next
     * rotation moves into the archive.
     */
    public function recent(Label $label): int
    {
        return $label->isSpam() ? $this->recentSpam : $this->recentHam;
    }

    /**
     * Texts of the class learned and not unlearned, whatever their age.
     */
    public function learned(Label $label): int
    {
        return $label->isSpam() ? $this->learnedSpam : $this->learnedHam;
    }
}
