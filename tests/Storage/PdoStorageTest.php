<?php

declare(strict_types=1);

// SPDX-License-Identifier: AGPL-3.0-or-later

use Gecka\SpamFilter\Generation;
use Gecka\SpamFilter\Label;
use Gecka\SpamFilter\SpamFilter;
use Gecka\SpamFilter\Storage\PdoStorage;
use Gecka\SpamFilter\Testing\StorageContract;

function sqliteStorage(int $bits = 10): PdoStorage
{
    $storage = new PdoStorage(new PDO('sqlite::memory:'));
    $storage->install($bits);

    return $storage;
}

it('honours the storage contract on SQLite', function (): void {
    StorageContract::verify(fn(int $bits) => sqliteStorage($bits));
})->throwsNoExceptions();

it('is idempotent on install', function (): void {
    $storage = sqliteStorage();
    $storage->apply([1 => 2], Label::Spam, 1);

    $storage->install(10);

    expect($storage->load()->count(Label::Spam, 1))->toBe(2);
    expect($storage->load()->bits)->toBe(10);
});

it('refuses another feature space once installed', function (): void {
    $storage = sqliteStorage(10);

    expect(fn() => $storage->install(12))->toThrow(InvalidArgumentException::class, 'installed with 10 bits');
});

it('joins a transaction the caller already opened', function (): void {
    $pdo = new PDO('sqlite::memory:');
    $storage = new PdoStorage($pdo);
    $storage->install(10);

    $pdo->beginTransaction();
    $storage->apply([1 => 2], Label::Spam, 1);
    expect($pdo->inTransaction())->toBeTrue();
    $pdo->rollBack();

    expect($storage->load()->count(Label::Spam, 1))->toBe(0);
    expect($storage->version())->toBe(0);
});

it('stores folded slots, never raw hashes', function (): void {
    $pdo = new PDO('sqlite::memory:');
    $storage = new PdoStorage($pdo);
    $storage->install(10);

    $storage->apply([5 + (1 << 10) => 1], Label::Ham, 1);

    $statement = $pdo->query('SELECT feature FROM spamfilter_counts');
    assert($statement !== false);
    expect($statement->fetchColumn())->toBe(5);
});

it('refuses to load before install', function (): void {
    $storage = new PdoStorage(new PDO('sqlite::memory:'));

    expect(fn() => $storage->load())->toThrow(RuntimeException::class);
});

it('refuses counts learned with another feature hash version', function (): void {
    $pdo = new PDO('sqlite::memory:');
    (new PdoStorage($pdo))->install(10);
    $pdo->exec("UPDATE spamfilter_meta SET value = value + 1 WHERE name = 'hash'");

    // A storage opened on that database afterwards
    expect(fn() => (new PdoStorage($pdo))->load())->toThrow(RuntimeException::class, 'relearned');
});

it('refuses tables laid out under another schema', function (): void {
    $pdo = new PDO('sqlite::memory:');
    (new PdoStorage($pdo))->install(10);
    $pdo->exec("UPDATE spamfilter_meta SET value = value + 1 WHERE name = 'schema'");

    expect(fn() => (new PdoStorage($pdo))->load())->toThrow(RuntimeException::class, 'migrated');
});

it('refuses an unsafe table prefix', function (): void {
    expect(fn() => new PdoStorage(new PDO('sqlite::memory:'), 'x; DROP TABLE y; --'))
        ->toThrow(InvalidArgumentException::class);
});

it('keeps the filter and the database in step', function (): void {
    $storage = sqliteStorage(12);
    $filter = new SpamFilter($storage->load(), storage: $storage);

    $filter->learn('Cheap backlinks for your site', Label::Spam);
    $filter->learn('Bonjour, ma facture est arrivée', Label::Ham);

    $reloaded = new SpamFilter($storage->load());
    $text = 'cheap backlinks facture';

    expect($reloaded->classify($text)->logOdds)->toBe($filter->classify($text)->logOdds);
    expect($reloaded->classify('backlinks')->logOdds)->toBeGreaterThan(0.0);
});

it('rotates the database and the snapshot alike', function (): void {
    $storage = sqliteStorage(12);
    $filter = new SpamFilter($storage->load(), storage: $storage);
    $filter->learn('Cheap backlinks for your site', Label::Spam);
    $filter->learn('Cheap backlinks for your site', Label::Spam);
    $filter->learn('Bonjour, ma facture est arrivée', Label::Ham);

    $filter->rotate();
    $once = $storage->load();
    $filter->rotate();
    $twice = $storage->load();

    expect($once->texts(Label::Spam))->toBe(2)
        ->and($once->texts(Label::Ham))->toBe(1)
        ->and($twice->texts(Label::Spam))->toBe(1)
        ->and($twice->texts(Label::Ham))->toBe(0)
        ->and($twice->total(Label::Ham))->toBe(0)
        ->and($twice->total(Label::Spam))->toBeGreaterThan(0)
        ->and($filter->generation())->toBe(2)
        ->and($storage->tally()->learned(Label::Spam))->toBe(2)
        ->and((new SpamFilter($twice))->classify('cheap backlinks facture')->logOdds)
        ->toBe($filter->classify('cheap backlinks facture')->logOdds);
});

it('drops the rows that a rotation emptied', function (): void {
    $pdo = new PDO('sqlite::memory:');
    $storage = new PdoStorage($pdo);
    $storage->install(10);
    $storage->apply([1 => 1, 2 => 2], Label::Spam, 1, Generation::Archive);

    $storage->rotate();

    $statement = $pdo->query('SELECT feature FROM spamfilter_counts ORDER BY feature');
    assert($statement !== false);
    expect($statement->fetchAll(PDO::FETCH_COLUMN))->toBe([2]);
});

it('returns from learn() the generation the text belongs to', function (): void {
    $storage = sqliteStorage(12);
    $filter = new SpamFilter($storage->load(), storage: $storage);

    expect($filter->learn('Cheap backlinks for your site', Label::Spam))->toBe(0)
        ->and($filter->learn('Cheap backlinks for your site', Label::Spam, Generation::Archive))->toBe(-1);

    $filter->rotate();

    expect($filter->learn('Cheap backlinks for your site', Label::Spam))->toBe(1)
        ->and($filter->learn('Cheap backlinks for your site', Label::Spam, Generation::Archive))->toBe(0)
        ->and((new SpamFilter(new Gecka\SpamFilter\Model\ClassCounts(10)))->learn('no storage', Label::Ham))->toBe(0);
});

it('unlearns a text exactly up to one rotation after it was learned', function (): void {
    $storage = sqliteStorage(12);
    $filter = new SpamFilter($storage->load(), storage: $storage);
    $filter->learn('Bonjour, ma facture est arrivée', Label::Ham);
    $learnedIn = $filter->learn('Cheap backlinks for your site', Label::Spam);
    $before = $storage->load()->total(Label::Spam);

    $filter->rotate();

    expect($filter->unlearn('Cheap backlinks for your site', Label::Spam, $learnedIn))->toBeTrue()
        ->and($storage->load()->total(Label::Spam))->toBe(0)
        ->and($before)->toBeGreaterThan(0)
        ->and($storage->load()->texts(Label::Spam))->toBe(0);
});

it('refuses to unlearn a text learned before the previous rotation', function (): void {
    $storage = sqliteStorage(12);
    $filter = new SpamFilter($storage->load(), storage: $storage);
    $filter->learn('Cheap backlinks for your site', Label::Spam);
    $filter->learn('Cheap backlinks for your site', Label::Spam);
    $filter->rotate();
    $filter->rotate();
    $snapshot = $storage->load()->toBinary(false);

    expect($filter->unlearn('Cheap backlinks for your site', Label::Spam, 0))->toBeFalse()
        ->and($storage->load()->toBinary(false))->toBe($snapshot);
});

it('refuses to unlearn from a generation that does not exist yet', function (): void {
    $storage = sqliteStorage(12);
    $filter = new SpamFilter($storage->load(), storage: $storage);
    $filter->learn('Cheap backlinks for your site', Label::Spam);

    expect(fn() => $filter->unlearn('Cheap backlinks for your site', Label::Spam, 1))->toThrow(InvalidArgumentException::class);
});

it('takes a text learned into the archive back from the archive', function (): void {
    $storage = sqliteStorage(12);
    $filter = new SpamFilter($storage->load(), storage: $storage);
    $filter->learn('Cheap backlinks for your site', Label::Spam);
    $learnedIn = $filter->learn('Cheap backlinks for your site', Label::Spam, Generation::Archive);

    expect($filter->unlearn('Cheap backlinks for your site', Label::Spam, $learnedIn))->toBeTrue()
        ->and($storage->tally()->recent(Label::Spam))->toBe(1)
        ->and($storage->load()->texts(Label::Spam))->toBe(1);
});

it('cannot rotate without a storage', function (): void {
    expect(fn() => (new SpamFilter(new Gecka\SpamFilter\Model\ClassCounts(10)))->rotate())->toThrow(LogicException::class);
});
