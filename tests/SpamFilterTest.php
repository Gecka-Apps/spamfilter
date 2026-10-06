<?php

declare(strict_types=1);

// SPDX-License-Identifier: AGPL-3.0-or-later

use Gecka\SpamFilter\Label;
use Gecka\SpamFilter\Model\ClassCounts;
use Gecka\SpamFilter\SpamFilter;

function filter(): SpamFilter
{
    return new SpamFilter(new ClassCounts(16));
}

it('knows nothing at first', function (): void {
    $score = filter()->classify('Bonjour, je souhaite un devis.');

    expect($score->logOdds)->toBe(0.0);
    expect($score->probability())->toBe(0.5);
    expect($score->occurrences)->toBeGreaterThan(0);
});

it('separates spam from ham after learning a few texts', function (): void {
    $f = filter();
    $f->learn('Boost your SEO ranking with cheap backlinks, free audit at seo-boost.example', Label::Spam);
    $f->learn('We offer affordable SEO backlinks packages, reply for a free quote', Label::Spam);
    $f->learn('Bonjour, j\'ai un problème avec ma facture de mars, pouvez-vous me rappeler ?', Label::Ham);
    $f->learn('Merci pour votre réponse rapide, le colis est bien arrivé.', Label::Ham);

    $spam = $f->classify('Free SEO audit and backlinks for your site, cheap packages');
    $ham = $f->classify('Bonjour, ma facture est arrivée, merci pour le colis');

    expect($spam->logOdds)->toBeGreaterThan(0.0);
    expect($ham->logOdds)->toBeLessThan(0.0);
    expect($spam->probability())->toBeGreaterThan($ham->probability());
});

it('still ranks spam above ordinary text with spam only', function (): void {
    $f = filter();
    $f->learn('Boost your SEO ranking with cheap backlinks, free audit', Label::Spam);
    $f->learn('We offer affordable SEO backlinks packages, free quote', Label::Spam);
    $f->learn('Rank higher on Google with our SEO backlinks, free audit today', Label::Spam);

    $spam = $f->classify('Cheap SEO backlinks, free audit');
    $plain = $f->classify('Hello, we met at the conference, could you send me your slides?');

    expect($spam->meanLogOdds())->toBeGreaterThan($plain->meanLogOdds());
});

it('unlearns a text exactly', function (): void {
    $f = filter();
    $f->learn('Bonjour, ma facture est arrivée', Label::Ham);
    $before = $f->classify('facture arrivée')->logOdds;

    $learnedIn = $f->learn('Cheap backlinks for your site', Label::Spam);
    $f->unlearn('Cheap backlinks for your site', Label::Spam, $learnedIn);

    expect($f->classify('facture arrivée')->logOdds)->toBe($before);
    expect($f->classify('Cheap backlinks')->logOdds)->toBe(0.0);
});

it('explains a verdict with the strongest features first', function (): void {
    $f = filter();
    $f->learn('cheap backlinks cheap backlinks cheap backlinks', Label::Spam);
    $f->learn('invoice invoice invoice', Label::Ham);

    $explanation = $f->explain('cheap invoice');
    $features = array_map(fn($c) => $c->feature, $explanation);

    expect($features)->toContain('w:cheap', 'w:invoice');
    expect($explanation[0]->feature)->toBeIn(['w:cheap', 'w:invoice']);

    $byFeature = array_combine($features, $explanation);
    expect($byFeature['w:cheap']->logRatio)->toBeGreaterThan(0.0);
    expect($byFeature['w:invoice']->logRatio)->toBeLessThan(0.0);

    $totals = array_map(fn($c) => abs($c->total()), $explanation);
    $sorted = $totals;
    rsort($sorted);
    expect($totals)->toBe($sorted);
});

it('explains with the same weights it classifies with', function (): void {
    $site = new ClassCounts(16);
    $log = new SpamFilter($site, logCounts: true);
    $log->learn('spam spam spam spam', Label::Spam);
    $log->learn('invoice', Label::Ham);

    $text = 'spam spam spam spam spam spam spam spam';
    $sum = array_sum(array_map(fn($c) => $c->total(), $log->explain($text)));

    expect($sum)->toEqualWithDelta($log->classify($text)->logOdds, 1e-9);
});

it('can weigh repetitions logarithmically', function (): void {
    $site = new ClassCounts(16);
    $site->learn([1 => 1], Label::Spam);

    $linear = new SpamFilter($site);
    $log = new SpamFilter($site, logCounts: true);
    $linear->learn('spam spam spam spam spam spam spam spam', Label::Spam);

    $text = 'spam spam spam spam spam spam spam spam';
    expect($log->classify($text)->logOdds)->toBeLessThan($linear->classify($text)->logOdds);
    expect($log->classify($text)->logOdds)->toBeGreaterThan(0.0);
});
