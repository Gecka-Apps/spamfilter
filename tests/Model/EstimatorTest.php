<?php

declare(strict_types=1);

// SPDX-License-Identifier: AGPL-3.0-or-later

use Gecka\SpamFilter\Label;
use Gecka\SpamFilter\Model\ClassCounts;
use Gecka\SpamFilter\Model\CountTable;
use Gecka\SpamFilter\Model\Estimator;

it('scores an unknown feature at exactly zero', function (): void {
    $site = new ClassCounts(8);
    $site->learn([1 => 100], Label::Spam);
    $site->learn([2 => 10], Label::Ham);

    expect((new Estimator($site))->logRatio(3))->toBe(0.0);
});

it('scores nothing when nothing was learned', function (): void {
    expect((new Estimator(new ClassCounts(8)))->logRatio(1))->toBe(0.0);
});

it('leans towards the class a feature was seen in', function (): void {
    $site = new ClassCounts(8);
    $site->learn([1 => 5, 3 => 5], Label::Spam);
    $site->learn([2 => 5, 3 => 5], Label::Ham);
    $e = new Estimator($site);

    expect($e->logRatio(1))->toBeGreaterThan(0.0);
    expect($e->logRatio(2))->toBeLessThan(0.0);
    expect($e->logRatio(3))->toEqualWithDelta(0.0, 1e-9);
    expect($e->logRatio(1))->toEqualWithDelta(-$e->logRatio(2), 1e-9);
});

it('scores every known feature alike with spam only and no background', function (): void {
    // The fallback background is the spam distribution itself: every lift is
    // 1, so familiar features all score ln(1 + 1/μ)
    $site = new ClassCounts(8);
    $site->learn([1 => 100, 2 => 1], Label::Spam);
    $e = new Estimator($site, backgroundWeight: 10.0, alpha: 0.0001);

    expect($e->logRatio(1))->toEqualWithDelta(log(1.1), 1e-3);
    expect($e->logRatio(2))->toEqualWithDelta(log(1.1), 1e-2);
});

it('tells common words from rare ones given a language background and spam only', function (): void {
    $background = new CountTable(256);
    $background->add(1, 1000); // "bonjour": everywhere in plain language
    $background->add(2, 1);    // "backlinks": almost never
    $background->add(3, 10);

    $site = new ClassCounts(8);
    $site->learn([1 => 10, 2 => 10], Label::Spam);
    $e = new Estimator($site, background: $background, backgroundWeight: 10.0);

    // Half of the spam mass but almost all of plain text: no lift, about neutral
    expect($e->logRatio(1))->toBeGreaterThan(0.0);
    expect($e->logRatio(1))->toBeLessThan(0.1);
    // Half of the spam mass, almost absent from plain text: a large lift
    expect($e->logRatio(2))->toBeGreaterThan(2.0);
    // Never seen in spam: nothing to say
    expect($e->logRatio(3))->toBe(0.0);
});

it('weighs the pre-trained layer against site counts with the configured weight', function (): void {
    $pretrained = new ClassCounts(8);
    $pretrained->learn([1 => 10, 3 => 90], Label::Spam);
    $pretrained->learn([2 => 10, 3 => 90], Label::Ham);

    // The site disagrees: feature 1 appears in its ham
    $site = new ClassCounts(8);
    $site->learn([1 => 10, 3 => 90], Label::Ham);
    $site->learn([3 => 100], Label::Spam);

    $none = new Estimator($site, $pretrained, pretrainedWeight: 0.0);
    $half = new Estimator($site, $pretrained, pretrainedWeight: 0.5);
    $full = new Estimator($site, $pretrained, pretrainedWeight: 1.0);

    expect($none->logRatio(1))->toBeLessThan($half->logRatio(1));
    expect($half->logRatio(1))->toBeLessThan($full->logRatio(1));
});

it('lets site corrections override the pre-trained layer', function (): void {
    $pretrained = new ClassCounts(8);
    $pretrained->learn([1 => 10, 3 => 90], Label::Spam);
    $pretrained->learn([2 => 10, 3 => 90], Label::Ham);

    $site = new ClassCounts(8);
    $before = (new Estimator($site, $pretrained))->logRatio(1);

    $site->learn([1 => 50, 3 => 50], Label::Ham);
    $after = (new Estimator($site, $pretrained))->logRatio(1);

    expect($before)->toBeGreaterThan(0.0);
    expect($after)->toBeLessThan(0.0);
});

it('refuses weights that would divide by zero', function (): void {
    expect(fn() => new Estimator(new ClassCounts(8), alpha: 0.0))->toThrow(InvalidArgumentException::class);
    expect(fn() => new Estimator(new ClassCounts(8), backgroundWeight: 0.0))->toThrow(InvalidArgumentException::class);
    expect(fn() => new Estimator(new ClassCounts(8), pretrainedWeight: -1.0))->toThrow(InvalidArgumentException::class);
});

it('works with a background table larger than the site layer', function (): void {
    $background = new CountTable(1 << 12);
    $background->add(1, 1000);
    $background->add(2, 1);

    $site = new ClassCounts(8);
    $site->learn([1 => 10, 2 => 10], Label::Spam);
    $e = new Estimator($site, background: $background, backgroundWeight: 10.0);

    expect($e->logRatio(1))->toBeLessThan(0.1);
    expect($e->logRatio(2))->toBeGreaterThan(2.0);
});
