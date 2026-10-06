<?php

declare(strict_types=1);

// SPDX-License-Identifier: AGPL-3.0-or-later

use Gecka\SpamFilter\Generation;
use Gecka\SpamFilter\Label;
use Gecka\SpamFilter\Model\ClassCounts;
use Gecka\SpamFilter\Storage\FileSnapshotCache;
use Gecka\SpamFilter\Storage\Storage;
use Gecka\SpamFilter\Storage\Tally;

/**
 * An in-memory storage that counts how often the snapshot is rebuilt.
 */
final class CountingStorage implements Storage
{
    public int $loads = 0;

    private ClassCounts $counts;

    private ClassCounts $archive;

    private int $version = 0;

    private int $generation = 0;

    public function __construct(int $bits = 8, private readonly string $identity = 'counting')
    {
        $this->counts = new ClassCounts($bits);
        $this->archive = new ClassCounts($bits);
    }

    public function load(): ClassCounts
    {
        $this->loads++;

        return $this->archive->plus($this->counts);
    }

    public function apply(array $hashed, Label $label, int $sign, Generation $generation = Generation::Recent): int
    {
        $counts = $generation === Generation::Recent ? $this->counts : $this->archive;
        $sign > 0 ? $counts->learn($hashed, $label) : $counts->unlearn($hashed, $label);
        $this->version++;

        return $this->generation;
    }

    public function rotate(): void
    {
        $this->archive->halve();
        $this->archive = $this->archive->plus($this->counts);
        $this->counts = new ClassCounts($this->counts->bits);
        $this->generation++;
        $this->version++;
    }

    public function tally(): Tally
    {
        return new Tally($this->generation, $this->counts->texts(Label::Spam), $this->counts->texts(Label::Ham), 0, 0);
    }

    public function version(): int
    {
        return $this->version;
    }

    public function identity(): string
    {
        return $this->identity;
    }
}

function snapshotPath(): string
{
    $directory = sys_get_temp_dir() . '/spamfilter-' . bin2hex(random_bytes(6));

    return "$directory/site.snapshot";
}

afterEach(function (): void {
    foreach (glob(sys_get_temp_dir() . '/spamfilter-*/*') ?: [] as $file) {
        unlink($file);
    }
    foreach (glob(sys_get_temp_dir() . '/spamfilter-*') ?: [] as $directory) {
        rmdir($directory);
    }
});

it('loads from the storage once and from the file afterwards', function (): void {
    $storage = new CountingStorage();
    $storage->apply([1 => 2], Label::Spam, 1);
    $path = snapshotPath();
    $cache = new FileSnapshotCache($storage, $path);

    $first = $cache->load();
    $second = $cache->load();

    expect($storage->loads)->toBe(1);
    expect($second->toBinary(false))->toBe($first->toBinary(false));
    expect($second->count(Label::Spam, 1))->toBe(2);
    expect(is_file($path))->toBeTrue();
});

it('creates a private directory and a private file', function (): void {
    $path = snapshotPath();
    (new FileSnapshotCache(new CountingStorage(), $path))->load();

    expect(fileperms(dirname($path)) & 0777)->toBe(0700);
    expect(fileperms($path) & 0777)->toBe(0600);
});

it('rebuilds the snapshot when the storage version moves', function (): void {
    $storage = new CountingStorage();
    $cache = new FileSnapshotCache($storage, snapshotPath());
    $cache->load();

    $storage->apply([3 => 1], Label::Ham, 1);
    $fresh = $cache->load();

    expect($storage->loads)->toBe(2);
    expect($fresh->count(Label::Ham, 3))->toBe(1);
});

it('ignores a file written for another storage at the same version', function (): void {
    $path = snapshotPath();
    $first = new CountingStorage();
    $first->apply([1 => 2], Label::Spam, 1);
    (new FileSnapshotCache($first, $path))->load();

    $second = new CountingStorage(identity: 'another');
    $second->apply([3 => 1], Label::Ham, 1);
    $counts = (new FileSnapshotCache($second, $path))->load();

    expect($first->version())->toBe($second->version());
    expect($second->loads)->toBe(1);
    expect($counts->count(Label::Spam, 1))->toBe(0);
    expect($counts->count(Label::Ham, 3))->toBe(1);
});

it('ignores a damaged file', function (): void {
    $storage = new CountingStorage();
    $path = snapshotPath();
    $cache = new FileSnapshotCache($storage, $path);
    $cache->load();

    // A truncated model: the right header, no tables
    file_put_contents($path, pack('J', $storage->version()) . "GSFC\x03" . str_repeat("\0", 10));
    $counts = $cache->load();

    expect($storage->loads)->toBe(2);
    expect($counts->bits)->toBe(8);
});

it('ignores a symbolic link in place of the file', function (): void {
    $storage = new CountingStorage();
    $path = snapshotPath();
    $cache = new FileSnapshotCache($storage, $path);
    $cache->load();

    $target = dirname($path) . '/planted';
    rename($path, $target);
    symlink($target, $path);
    $cache->load();

    expect($storage->loads)->toBe(2);
    expect(is_link($path))->toBeFalse();
});

it('ignores a file with permission bits beyond its mode, and replaces it', function (): void {
    $storage = new CountingStorage();
    $path = snapshotPath();
    $cache = new FileSnapshotCache($storage, $path);
    $cache->load();

    chmod($path, 0644);
    $cache->load();

    expect($storage->loads)->toBe(2);
    expect(fileperms($path) & 0777)->toBe(0600);
});

it('accepts such a file when the check is off', function (): void {
    $storage = new CountingStorage();
    $path = snapshotPath();
    $cache = new FileSnapshotCache($storage, $path, strict: false);
    $cache->load();

    chmod($path, 0644);
    $cache->load();

    expect($storage->loads)->toBe(1);
});

it('writes a group mode and the matching directory mode', function (): void {
    $path = snapshotPath();
    (new FileSnapshotCache(new CountingStorage(), $path, mode: 0660))->load();

    expect(fileperms($path) & 0777)->toBe(0660);
    expect(fileperms(dirname($path)) & 0777)->toBe(0770);
});

it('refuses a mode the owner could not use', function (): void {
    expect(fn() => new FileSnapshotCache(new CountingStorage(), snapshotPath(), mode: 0400))
        ->toThrow(InvalidArgumentException::class);
    expect(fn() => new FileSnapshotCache(new CountingStorage(), snapshotPath(), mode: 01600))
        ->toThrow(InvalidArgumentException::class);
});
