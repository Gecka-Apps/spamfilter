<?php

declare(strict_types=1);

// SPDX-License-Identifier: AGPL-3.0-or-later

use Gecka\SpamFilter\Label;
use Gecka\SpamFilter\Storage\PdoStorage;
use Gecka\SpamFilter\Testing\StorageContract;

/*
 * Runs the storage contract against real servers when compose.yaml (or the
 * environment) provides them; skips otherwise.
 */

/**
 * @return array{0: string, 1: string, 2: string}|null DSN, user, password
 */
function serverCredentials(string $driver): ?array
{
    $prefix = 'SPAMFILTER_TEST_' . strtoupper($driver) . '_';
    $dsn = getenv($prefix . 'DSN');
    if (! is_string($dsn) || $dsn === '') {
        return null;
    }

    return [$dsn, (string) getenv($prefix . 'USER'), (string) getenv($prefix . 'PASSWORD')];
}

/**
 * A table prefix no other test in this run uses.
 */
function freshPrefix(): string
{
    static $sequence = 0;

    return 'sft' . (++$sequence) . '_';
}

/**
 * Installs a storage on its own tables, dropped first in case a previous run
 * left them behind.
 */
function installOn(PDO $pdo, string $prefix, int $bits): PdoStorage
{
    $pdo->exec("DROP TABLE IF EXISTS {$prefix}counts");
    $pdo->exec("DROP TABLE IF EXISTS {$prefix}meta");

    $storage = new PdoStorage($pdo, $prefix);
    $storage->install($bits);

    return $storage;
}

foreach (['mysql', 'pgsql'] as $driver) {
    it("honours the storage contract on $driver", function () use ($driver): void {
        $credentials = serverCredentials($driver);
        if ($credentials === null) {
            $this->markTestSkipped('No SPAMFILTER_TEST_' . strtoupper($driver) . '_DSN in the environment');
        }

        $pdo = new PDO(...$credentials);

        StorageContract::verify(fn(int $bits) => installOn($pdo, freshPrefix(), $bits));
    })->throwsNoExceptions();

    it("keeps every update when two connections learn at once on $driver", function () use ($driver): void {
        $credentials = serverCredentials($driver);
        if ($credentials === null) {
            $this->markTestSkipped('No SPAMFILTER_TEST_' . strtoupper($driver) . '_DSN in the environment');
        }

        $prefix = freshPrefix();
        $a = installOn(new PDO(...$credentials), $prefix, 10);
        $b = new PdoStorage(new PDO(...$credentials), $prefix);

        for ($i = 0; $i < 20; $i++) {
            $a->apply([1 => 1, 2 => 2], Label::Spam, 1);
            $b->apply([1 => 1, 3 => 1], Label::Ham, 1);
        }

        $counts = $b->load();
        expect($counts->count(Label::Spam, 1))->toBe(20);
        expect($counts->count(Label::Spam, 2))->toBe(40);
        expect($counts->count(Label::Ham, 1))->toBe(20);
        expect($counts->count(Label::Ham, 3))->toBe(20);
        expect($counts->texts(Label::Spam))->toBe(20);
        expect($counts->texts(Label::Ham))->toBe(20);
        expect($a->version())->toBe(40);
    });
}
