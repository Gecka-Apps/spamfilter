<?php

declare(strict_types=1);

// SPDX-License-Identifier: AGPL-3.0-or-later

use Gecka\SpamFilter\Model\CountTable;

it('starts empty', function (): void {
    $t = new CountTable(16);

    expect($t->get(0))->toBe(0);
    expect($t->get(15))->toBe(0);
    expect($t->total())->toBe(0);
    expect($t->occupied())->toBe(0);
});

it('adds and subtracts, keeping the running total', function (): void {
    $t = new CountTable(16);

    $t->add(3, 5);
    $t->add(3, 2);
    $t->add(9, 1);

    expect($t->get(3))->toBe(7);
    expect($t->get(9))->toBe(1);
    expect($t->total())->toBe(8);
    expect($t->occupied())->toBe(2);

    $t->add(3, -7);
    expect($t->get(3))->toBe(0);
    expect($t->total())->toBe(1);
});

it('never goes below zero or above the uint32 range', function (): void {
    $t = new CountTable(4);

    $t->add(1, -10);
    expect($t->get(1))->toBe(0);

    $t->add(2, 0xFFFFFFFF);
    $t->add(2, 10);
    expect($t->get(2))->toBe(0xFFFFFFFF);
    expect($t->total())->toBe(0xFFFFFFFF);
});

it('stores large values in big-endian bytes', function (): void {
    $t = new CountTable(2);

    $t->add(1, 0x01020304);

    expect($t->toBinary())->toBe("\0\0\0\0\x01\x02\x03\x04");
});

it('round-trips through its binary form', function (): void {
    $t = new CountTable(8);
    $t->add(0, 1);
    $t->add(7, 123456789);

    $copy = CountTable::fromBinary($t->toBinary());

    expect($copy->size)->toBe(8);
    expect($copy->get(0))->toBe(1);
    expect($copy->get(7))->toBe(123456789);
    expect($copy->total())->toBe(123456790);
});

it('folds any hash into its size', function (): void {
    $t = new CountTable(16);

    $t->add(5, 1);
    $t->add(5 + 16, 1);
    $t->add(5 + 32 * 1000, 1);

    expect($t->get(5))->toBe(3);
    expect($t->get(21))->toBe(3);
    expect($t->bits())->toBe(4);
});

it('requires a power of two within the ceiling', function (): void {
    expect(fn() => new CountTable(1000))->toThrow(InvalidArgumentException::class);
    expect(fn() => new CountTable(0))->toThrow(InvalidArgumentException::class);
    expect(fn() => new CountTable(1 << (CountTable::MAX_BITS + 1)))->toThrow(InvalidArgumentException::class);
});

it('rejects malformed binary data', function (): void {
    expect(fn() => CountTable::fromBinary('abc'))->toThrow(InvalidArgumentException::class);
    expect(fn() => CountTable::fromBinary(''))->toThrow(InvalidArgumentException::class);
});

it('halves every counter, rounding down', function (): void {
    $t = new CountTable(8);
    $t->add(0, 7);
    $t->add(1, 1);
    $t->add(2, 0xFFFFFFFF);

    $t->halve();

    expect($t->get(0))->toBe(3);
    expect($t->get(1))->toBe(0);
    expect($t->get(2))->toBe(0x7FFFFFFF);
    expect($t->total())->toBe(3 + 0x7FFFFFFF);
    expect($t->occupied())->toBe(2);
});
