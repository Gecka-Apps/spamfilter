<?php

declare(strict_types=1);

// SPDX-License-Identifier: AGPL-3.0-or-later

namespace Gecka\SpamFilter\Model;

use Gecka\SpamFilter\Label;

/**
 * Computes, for one feature, how much more likely it is in spam than in
 * legitimate text.
 *
 * Two layers of counts are combined: the site's own (weight 1) and an optional
 * pre-trained layer (weight $pretrainedWeight), giving a relative frequency
 * f_c(w) per class. Each is compared with the feature's background frequency
 * P_bg(w), and the two lifts are set against each other with a floor μ:
 *
 *   r(w) = ln( (f_spam(w) / P_bg(w) + μ) / (f_ham(w) / P_bg(w) + μ) )
 *
 * The background is a table of plain-language frequencies when one is given,
 * otherwise the feature's share of everything learned regardless of class.
 * Every slot of it carries a pseudo-count of α times the table's mean count
 * per slot, so a feature the background has never seen is rare rather than
 * impossible, and the same α means the same thing on a table of twenty
 * million occurrences and on one of twenty thousand.
 *
 * A feature never seen scores exactly 0, and the ratio is bounded by how far
 * a lift can go. With spam only and a language background, a word as common
 * in spam as in plain text scores ln(1 + 1/μ), negligible for μ around 10,
 * while a word frequent in spam but rare in plain text scores several units.
 * With spam only and no background table, the fallback background is the spam
 * distribution itself and every known feature scores that same ln(1 + 1/μ):
 * familiar means spam-like, nothing more, until legitimate text, a
 * pre-trained layer or a background table is available.
 *
 * @author Laurent Dinclaux <laurent@gecka.nc>
 * @copyright Gecka <contact@gecka.nc>
 * @license AGPL-3.0-or-later
 */
final class Estimator
{
    /**
     * @param CountTable|null $background Plain-language feature frequencies, in a table of any size
     * @param float $pretrainedWeight How much a pre-trained count weighs against a site count
     * @param float $backgroundWeight μ, the lift a feature needs over its background frequency to matter
     * @param float $alpha Pseudo-count given to every background slot, as a share of the table's mean count per slot
     */
    public function __construct(
        private readonly ClassCounts $site,
        private readonly ?ClassCounts $pretrained = null,
        private readonly ?CountTable $background = null,
        private readonly float $pretrainedWeight = 0.5,
        private readonly float $backgroundWeight = 10.0,
        private readonly float $alpha = 0.2,
    ) {
        if ($backgroundWeight <= 0.0 || $alpha <= 0.0) {
            throw new \InvalidArgumentException('backgroundWeight and alpha must be positive');
        }
        if ($pretrainedWeight < 0.0) {
            throw new \InvalidArgumentException('pretrainedWeight must not be negative');
        }
    }

    /**
     * Log-likelihood ratio of one feature, positive towards spam.
     */
    public function logRatio(int $index): float
    {
        $background = $this->backgroundProbability($index);

        $spam = $this->frequency(Label::Spam, $index) / $background + $this->backgroundWeight;
        $ham = $this->frequency(Label::Ham, $index) / $background + $this->backgroundWeight;

        return log($spam / $ham);
    }

    /**
     * Relative frequency of the feature in the class, over both layers.
     */
    private function frequency(Label $label, int $index): float
    {
        $count = (float) $this->site->count($label, $index);
        $total = (float) $this->site->total($label);

        if ($this->pretrained !== null) {
            $count += $this->pretrainedWeight * $this->pretrained->count($label, $index);
            $total += $this->pretrainedWeight * $this->pretrained->total($label);
        }

        return $total > 0 ? $count / $total : 0.0;
    }

    /**
     * Share of the feature in plain language, or failing a background table in
     * all learned text with classes merged. The pseudo-count keeps an unseen
     * feature at a small non-zero probability; an empty table makes every
     * feature equally likely.
     */
    private function backgroundProbability(int $index): float
    {
        if ($this->background !== null) {
            return self::smoothed(
                (float) $this->background->get($index),
                (float) $this->background->total(),
                $this->background->size,
                $this->alpha,
            );
        }

        $size = 1 << $this->site->bits;
        $count = (float) ($this->site->count(Label::Spam, $index) + $this->site->count(Label::Ham, $index));
        $total = (float) ($this->site->total(Label::Spam) + $this->site->total(Label::Ham));

        if ($this->pretrained !== null) {
            $count += $this->pretrainedWeight
                * ($this->pretrained->count(Label::Spam, $index) + $this->pretrained->count(Label::Ham, $index));
            $total += $this->pretrainedWeight
                * ($this->pretrained->total(Label::Spam) + $this->pretrained->total(Label::Ham));
        }

        return self::smoothed($count, $total, $size, $this->alpha);
    }

    /**
     * (count + α × mean) / (total + α × total), the mean being total / size.
     */
    public static function smoothed(float $count, float $total, int $size, float $alpha): float
    {
        if ($total <= 0.0) {
            return 1.0 / $size;
        }

        return ($count + $alpha * $total / $size) / ($total * (1.0 + $alpha));
    }
}
