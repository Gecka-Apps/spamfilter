<?php

declare(strict_types=1);

// SPDX-License-Identifier: AGPL-3.0-or-later

use Gecka\SpamFilter\Label;
use Gecka\SpamFilter\Model\ClassCounts;

it('learns into the right class and counts texts', function (): void {
    $c = new ClassCounts(8);

    $c->learn([1 => 2, 2 => 1], Label::Spam);
    $c->learn([2 => 3], Label::Ham);

    expect($c->count(Label::Spam, 1))->toBe(2);
    expect($c->count(Label::Spam, 2))->toBe(1);
    expect($c->count(Label::Ham, 2))->toBe(3);
    expect($c->count(Label::Ham, 1))->toBe(0);
    expect($c->total(Label::Spam))->toBe(3);
    expect($c->total(Label::Ham))->toBe(3);
    expect($c->texts(Label::Spam))->toBe(1);
    expect($c->texts(Label::Ham))->toBe(1);
});

it('unlearns exactly what was learned', function (): void {
    $c = new ClassCounts(8);
    $c->learn([1 => 2, 2 => 1], Label::Spam);
    $before = $c->toBinary();

    $c->learn([1 => 5, 7 => 1], Label::Spam);
    $c->unlearn([1 => 5, 7 => 1], Label::Spam);

    expect($c->toBinary())->toBe($before);
    expect($c->texts(Label::Spam))->toBe(1);
});

it('does not go negative when unlearning something never learned', function (): void {
    $c = new ClassCounts(8);

    $c->unlearn([1 => 5], Label::Ham);

    expect($c->count(Label::Ham, 1))->toBe(0);
    expect($c->texts(Label::Ham))->toBe(0);
});

it('round-trips through its compressed binary form', function (): void {
    $c = new ClassCounts(10);
    $c->learn([5 => 2, 1000 => 1], Label::Spam);
    $c->learn([5 => 1], Label::Ham);
    $c->learn([6 => 4], Label::Ham);

    $copy = ClassCounts::fromBinary($c->toBinary());

    expect($copy->bits)->toBe(10);
    expect($copy->count(Label::Spam, 5))->toBe(2);
    expect($copy->count(Label::Spam, 1000))->toBe(1);
    expect($copy->count(Label::Ham, 6))->toBe(4);
    expect($copy->total(Label::Ham))->toBe(5);
    expect($copy->texts(Label::Spam))->toBe(1);
    expect($copy->texts(Label::Ham))->toBe(2);
});

it('sums both classes into a marginal table', function (): void {
    $c = new ClassCounts(8);
    $c->learn([1 => 2, 3 => 1], Label::Spam);
    $c->learn([1 => 5, 2 => 4], Label::Ham);

    $m = $c->marginal();

    expect($m->size)->toBe(256);
    expect($m->get(1))->toBe(7);
    expect($m->get(2))->toBe(4);
    expect($m->get(3))->toBe(1);
    expect($m->total())->toBe(12);
});

it('compresses an empty model to a few bytes', function (): void {
    $c = new ClassCounts(20);

    expect(strlen($c->toBinary()))->toBeLessThan(20000);
});

it('rejects a model built with another feature hash version', function (): void {
    $raw = (new ClassCounts(8))->toBinary(false);
    // The hash version is the first byte after the five-byte magic
    $raw[5] = chr((ord($raw[5]) + 1) % 256);

    expect(fn() => ClassCounts::fromBinary($raw))->toThrow(InvalidArgumentException::class, 'hash version');
});

it('rejects foreign data', function (): void {
    expect(fn() => ClassCounts::fromBinary((string) gzcompress('nope')))->toThrow(InvalidArgumentException::class);
});

it('halves both classes and the text counts', function (): void {
    $c = new ClassCounts(8);
    $c->learn([1 => 4, 2 => 1], Label::Spam);
    $c->learn([1 => 3], Label::Ham);
    $c->learn([3 => 1], Label::Ham);
    $c->learn([3 => 1], Label::Ham);

    $c->halve();

    expect($c->count(Label::Spam, 1))->toBe(2);
    expect($c->count(Label::Spam, 2))->toBe(0);
    expect($c->count(Label::Ham, 1))->toBe(1);
    expect($c->count(Label::Ham, 3))->toBe(1);
    expect($c->total(Label::Spam))->toBe(2);
    expect($c->total(Label::Ham))->toBe(2);
    expect($c->texts(Label::Spam))->toBe(0);
    expect($c->texts(Label::Ham))->toBe(1);
});
