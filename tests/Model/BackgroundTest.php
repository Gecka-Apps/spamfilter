<?php

declare(strict_types=1);

// SPDX-License-Identifier: AGPL-3.0-or-later

use Gecka\SpamFilter\Model\Background;
use Gecka\SpamFilter\Model\CountTable;
use Gecka\SpamFilter\Tokenizer\FeatureHasher;

it('round-trips a table through its binary form', function (): void {
    $table = new CountTable(1024);
    $table->add(3, 7);
    $table->add(1023, 123456);

    $copy = Background::fromBinary(Background::toBinary($table));

    expect($copy->size)->toBe(1024);
    expect($copy->get(3))->toBe(7);
    expect($copy->get(1023))->toBe(123456);
    expect($copy->total())->toBe(123463);
});

it('writes and reads a file', function (): void {
    $dir = sys_get_temp_dir() . '/spamfilter-test-' . bin2hex(random_bytes(4));
    $path = "$dir/nested/background.bin";

    $table = new CountTable(256);
    $table->add(10, 5);
    Background::write($table, $path);

    $read = Background::read($path);
    expect($read->get(10))->toBe(5);
    expect($read->total())->toBe(5);

    unlink($path);
    rmdir(dirname($path));
    rmdir($dir);
});

it('refuses a table built with another feature hash version', function (): void {
    $raw = (string) gzuncompress(Background::toBinary(new CountTable(256)));
    $raw[5] = chr((ord($raw[5]) + 1) % 256);

    expect(fn() => Background::fromBinary((string) gzcompress($raw)))
        ->toThrow(InvalidArgumentException::class, 'hash version');
});

it('refuses a table larger than the ceiling without inflating it', function (): void {
    // A 2^26 table of zeros, 256 MB, compressed in a stream so the test
    // itself never holds it; gzip shrinks it to a few hundred kilobytes
    $deflate = deflate_init(ZLIB_ENCODING_DEFLATE, ['level' => 9]);
    assert($deflate !== false);
    $bomb = deflate_add($deflate, "GSFB\x02" . pack('CCJ', FeatureHasher::VERSION, 26, 0), ZLIB_NO_FLUSH);
    $chunk = str_repeat("\0", 4 * 1024 * 1024);
    for ($i = 0; $i < 64; $i++) {
        $bomb .= deflate_add($deflate, $chunk, ZLIB_NO_FLUSH);
    }
    $bomb .= deflate_add($deflate, '', ZLIB_FINISH);
    unset($chunk);
    $before = memory_get_peak_usage(true);

    expect(strlen($bomb))->toBeLessThan(1024 * 1024);
    expect(fn() => Background::fromBinary($bomb))->toThrow(InvalidArgumentException::class);
    // Inflation stops at the 64 MB ceiling; the 256 MB the stream claims never materialise
    expect(memory_get_peak_usage(true) - $before)->toBeLessThan(192 * 1024 * 1024);
});

it('refuses a truncated table', function (): void {
    $table = new CountTable(256);
    $table->add(1, 1);
    $raw = (string) gzuncompress(Background::toBinary($table));

    expect(fn() => Background::fromBinary((string) gzcompress(substr($raw, 0, -4))))
        ->toThrow(InvalidArgumentException::class, 'Truncated');
    expect(fn() => Background::fromBinary((string) gzcompress($raw . 'xx')))
        ->toThrow(InvalidArgumentException::class, 'padded');
});

it('refuses foreign data', function (): void {
    expect(fn() => Background::fromBinary((string) gzcompress('nope')))->toThrow(InvalidArgumentException::class);
});
