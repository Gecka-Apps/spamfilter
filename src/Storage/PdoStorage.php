<?php

declare(strict_types=1);

// SPDX-License-Identifier: AGPL-3.0-or-later

namespace Gecka\SpamFilter\Storage;

use Gecka\SpamFilter\Generation;
use Gecka\SpamFilter\Label;
use Gecka\SpamFilter\Model\ClassCounts;
use Gecka\SpamFilter\Tokenizer\FeatureHasher;
use PDO;

/**
 * Site layer in a SQLite, MySQL/MariaDB or PostgreSQL database through PDO.
 *
 * Two tables: one row per feature slot holding the recent and the archived
 * counter of each class, and a small key/value table for the feature space
 * size, the schema and feature hash versions, the text counters of each
 * generation, the texts learned in all, the generation and version numbers
 * and a random installation id. Every change
 * is an upsert that adds a delta to the stored value inside one transaction,
 * so two texts learned at the same time both count. The transaction is the
 * caller's when one is already open on the connection.
 *
 * @author Laurent Dinclaux <laurent@gecka.nc>
 * @copyright Gecka <contact@gecka.nc>
 * @license AGPL-3.0-or-later
 */
final class PdoStorage implements Storage
{
    private readonly string $counts;

    private readonly string $meta;

    /** @var 'mysql'|'pgsql'|'sqlite' */
    private readonly string $dialect;

    /**
     * Layout of the two tables. Recorded in the key/value table at install
     * and checked on every open, so a library expecting another layout
     * refuses the tables instead of misreading them.
     */
    public const SCHEMA = 1;

    /**
     * Rows of the key/value table, with the value a fresh install gives them.
     */
    private const META = [
        'bits' => 0,
        'hash' => 0,
        'schema' => self::SCHEMA,
        'texts_ham' => 0,
        'texts_spam' => 0,
        'archive_texts_ham' => 0,
        'archive_texts_spam' => 0,
        'learned_ham' => 0,
        'learned_spam' => 0,
        'generation' => 0,
        'version' => 0,
        'install_id' => 0,
    ];

    /** @var array<key-of<self::META>, int>|null */
    private ?array $meta_ = null;

    /**
     * @param PDO $pdo Connection to a SQLite, MySQL/MariaDB or PostgreSQL database
     * @param string $prefix Start of both table names, letters, digits and underscores only
     */
    public function __construct(
        private readonly PDO $pdo,
        private readonly string $prefix = 'spamfilter_',
    ) {
        if (preg_match('/^[A-Za-z0-9_]*$/', $prefix) !== 1) {
            throw new \InvalidArgumentException('The table prefix may only contain letters, digits and underscores');
        }

        $driver = (string) $pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
        if (! in_array($driver, ['mysql', 'pgsql', 'sqlite'], true)) {
            throw new \InvalidArgumentException("Unsupported PDO driver \"$driver\": sqlite, mysql and pgsql are known");
        }

        $this->dialect = $driver;
        $this->counts = $prefix . 'counts';
        $this->meta = $prefix . 'meta';
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    }

    /**
     * Creates the tables when they do not exist yet. Safe to call on every
     * request, cheap once the tables are there. The feature space size is
     * fixed at the first install; a different value afterwards is refused.
     */
    public function install(int $bits = 20): void
    {
        if ($bits < 8 || $bits > 30) {
            throw new \InvalidArgumentException('bits must be between 8 and 30');
        }

        $integer = $this->dialect === 'sqlite' ? 'INTEGER' : 'BIGINT';

        $this->pdo->exec("CREATE TABLE IF NOT EXISTS {$this->counts} (
            feature $integer NOT NULL PRIMARY KEY,
            count_ham $integer NOT NULL DEFAULT 0,
            count_spam $integer NOT NULL DEFAULT 0,
            archive_ham $integer NOT NULL DEFAULT 0,
            archive_spam $integer NOT NULL DEFAULT 0
        )");
        $this->pdo->exec("CREATE TABLE IF NOT EXISTS {$this->meta} (
            name VARCHAR(32) NOT NULL PRIMARY KEY,
            value $integer NOT NULL
        )");

        $insert = $this->pdo->prepare(match ($this->dialect) {
            'mysql' => "INSERT IGNORE INTO {$this->meta} (name, value) VALUES (?, ?)",
            'pgsql' => "INSERT INTO {$this->meta} (name, value) VALUES (?, ?) ON CONFLICT (name) DO NOTHING",
            'sqlite' => "INSERT OR IGNORE INTO {$this->meta} (name, value) VALUES (?, ?)",
        });
        $rows = ['bits' => $bits, 'hash' => FeatureHasher::VERSION, 'install_id' => random_int(1, PHP_INT_MAX)] + self::META;
        foreach ($rows as $name => $value) {
            $insert->bindValue(1, $name, PDO::PARAM_STR);
            $insert->bindValue(2, $value, PDO::PARAM_INT);
            $insert->execute();
        }

        $this->meta_ = null;
        $meta = $this->readMeta();
        if ($meta['bits'] !== $bits) {
            throw new \InvalidArgumentException(sprintf(
                'The storage was installed with %d bits, it cannot become %d: relearn into a fresh storage',
                $meta['bits'],
                $bits,
            ));
        }
    }

    /**
     * Rebuilds the site layer from every stored row, both generations added together.
     */
    public function load(): ClassCounts
    {
        $meta = $this->readMeta();

        $statement = $this->pdo->query("SELECT feature, count_ham + archive_ham, count_spam + archive_spam FROM {$this->counts}");
        if ($statement === false) {
            throw new \RuntimeException('Cannot read the counters');
        }

        $rows = (function () use ($statement): \Generator {
            while (($row = $statement->fetch(PDO::FETCH_NUM)) !== false) {
                yield [(int) $row[0], (int) $row[1], (int) $row[2]];
            }
        })();

        return ClassCounts::fromRows($meta['bits'], $rows, $meta['texts_spam'] + $meta['archive_texts_spam'], $meta['texts_ham'] + $meta['archive_texts_ham']);
    }

    /**
     * Upserts one text's deltas into one generation inside a transaction,
     * visiting slots in a fixed order. The generation row is locked first and
     * kept until the commit, so a rotation cannot slip between the counters
     * and the text counts of one text, and the number returned is the one
     * the text was written under.
     */
    public function apply(array $hashed, Label $label, int $sign, Generation $generation = Generation::Recent): int
    {
        $meta = $this->readMeta();

        // Fold the hashes into the feature space, adding up the ones that
        // land on the same slot, and visit slots in one fixed order so that
        // concurrent transactions take their row locks the same way
        $mask = (1 << $meta['bits']) - 1;
        $slots = [];
        foreach ($hashed as $hash => $count) {
            $slot = $hash & $mask;
            $slots[$slot] = ($slots[$slot] ?? 0) + $sign * $count;
        }
        ksort($slots);

        $class = $label->isSpam() ? 'spam' : 'ham';
        $recent = $generation === Generation::Recent;
        $column = ($recent ? 'count_' : 'archive_') . $class;
        $texts = ($recent ? 'texts_' : 'archive_texts_') . $class;
        $learned = 'learned_' . $class;

        // The delta is bound twice: VALUES() and excluded.* would hand the
        // update the clamped value of the new row, which turns a subtraction
        // into an addition of zero
        $upsert = $this->pdo->prepare(
            $this->dialect === 'mysql'
                ? "INSERT INTO {$this->counts} (feature, $column) VALUES (?, {$this->clamp('?')})
                   ON DUPLICATE KEY UPDATE $column = {$this->clamp("$column + ?")}"
                : "INSERT INTO {$this->counts} (feature, $column) VALUES (?, {$this->clamp('?')})
                   ON CONFLICT (feature) DO UPDATE SET $column = {$this->clamp("{$this->counts}.$column + ?")}",
        );
        $bump = $this->pdo->prepare("UPDATE {$this->meta} SET value = {$this->clamp('value + ?')} WHERE name = ?");

        $current = $this->transaction(function () use ($slots, $upsert, $bump, $sign, $texts, $learned): int {
            $current = $this->lockGeneration();

            foreach ($slots as $slot => $delta) {
                $upsert->bindValue(1, $slot, PDO::PARAM_INT);
                $upsert->bindValue(2, $delta, PDO::PARAM_INT);
                $upsert->bindValue(3, $delta, PDO::PARAM_INT);
                $upsert->execute();
            }

            foreach ([$texts, $learned] as $name) {
                $bump->bindValue(1, $sign, PDO::PARAM_INT);
                $bump->bindValue(2, $name, PDO::PARAM_STR);
                $bump->execute();
            }
            $bump->bindValue(1, 1, PDO::PARAM_INT);
            $bump->bindValue(2, 'version', PDO::PARAM_STR);
            $bump->execute();

            // Rows that reached zero everywhere carry no information any more;
            // only the touched ones can have, so only they are checked
            foreach (array_chunk(array_keys($slots), 500) as $chunk) {
                $placeholders = implode(',', array_fill(0, count($chunk), '?'));
                $delete = $this->pdo->prepare("DELETE FROM {$this->counts} WHERE feature IN ($placeholders) AND {$this->empty()}");
                foreach ($chunk as $i => $slot) {
                    $delete->bindValue($i + 1, $slot, PDO::PARAM_INT);
                }
                $delete->execute();
            }

            return $current;
        });

        $this->meta_ = null;

        return $current;
    }

    /**
     * Shifts every archived counter and text count right by one bit, adds the
     * recent ones to them, empties the recent generation, drops the rows left
     * empty and moves the generation and the version.
     */
    public function rotate(): void
    {
        $this->readMeta();

        // The metadata rows are locked before the counters are touched, the
        // order apply() follows too, so a text is never split between the
        // generations. Each assignment reads the value the row had before the
        // statement on PostgreSQL and SQLite, and MySQL assigns from left to
        // right, so the archive takes the recent count before it is emptied.
        // The shift rounds down on all three dialects, where integer division
        // would not
        $this->transaction(function (): void {
            $meta = $this->fetchMeta(lock: true);

            $this->pdo->exec("UPDATE {$this->counts} SET
                archive_ham = (archive_ham >> 1) + count_ham,
                archive_spam = (archive_spam >> 1) + count_spam,
                count_ham = 0,
                count_spam = 0");
            $this->pdo->exec("DELETE FROM {$this->counts} WHERE {$this->empty()}");

            $set = $this->pdo->prepare("UPDATE {$this->meta} SET value = ? WHERE name = ?");
            $values = [
                'archive_texts_ham' => ($meta['archive_texts_ham'] >> 1) + $meta['texts_ham'],
                'archive_texts_spam' => ($meta['archive_texts_spam'] >> 1) + $meta['texts_spam'],
                'texts_ham' => 0,
                'texts_spam' => 0,
                'generation' => $meta['generation'] + 1,
                'version' => $meta['version'] + 1,
            ];
            foreach ($values as $name => $value) {
                $set->bindValue(1, $value, PDO::PARAM_INT);
                $set->bindValue(2, $name, PDO::PARAM_STR);
                $set->execute();
            }
        });

        $this->meta_ = null;
    }

    /**
     * Generation number and text counts, read from the database every time.
     */
    public function tally(): Tally
    {
        $this->meta_ = null;
        $meta = $this->readMeta();

        return new Tally($meta['generation'], $meta['texts_spam'], $meta['texts_ham'], $meta['learned_spam'], $meta['learned_ham']);
    }

    /**
     * Number of changes applied since install, read from the database every time.
     */
    public function version(): int
    {
        $this->meta_ = null;

        return $this->readMeta()['version'];
    }

    /**
     * Dialect, prefix and the random id drawn at install, stable for the life of the tables.
     */
    public function identity(): string
    {
        return $this->dialect . ':' . $this->prefix . ':' . $this->readMeta()['install_id'];
    }

    /**
     * Runs $work inside a transaction, the caller's when one is already open
     * on the connection. On SQLite a transaction of its own takes the write
     * lock as it opens: a deferred one would read first, and a second writer
     * holding a read lock gets SQLITE_BUSY at its first write instead of
     * queueing, since waiting would deadlock the first writer's commit.
     *
     * @template T
     *
     * @param callable(): T $work
     * @return T
     */
    private function transaction(callable $work): mixed
    {
        $owns = ! $this->pdo->inTransaction();
        if ($owns) {
            $this->dialect === 'sqlite' ? $this->pdo->exec('BEGIN IMMEDIATE') : $this->pdo->beginTransaction();
        }

        try {
            $result = $work();

            if ($owns) {
                $this->pdo->commit();
            }

            return $result;
        } catch (\Throwable $e) {
            if ($owns) {
                // After a deadlock the server has already rolled back, and
                // rollBack() then throws; the original error is the one to keep
                try {
                    $this->pdo->rollBack();
                } catch (\PDOException) {
                }
            }
            throw $e;
        }
    }

    /**
     * SQL condition of a row holding nothing in either generation.
     */
    private function empty(): string
    {
        return 'count_ham = 0 AND count_spam = 0 AND archive_ham = 0 AND archive_spam = 0';
    }

    /**
     * Row lock clause of a SELECT, empty on SQLite where locks are on the
     * whole database.
     */
    private function forUpdate(): string
    {
        return $this->dialect === 'sqlite' ? '' : ' FOR UPDATE';
    }

    /**
     * SQL keeping an expression at zero or above.
     */
    private function clamp(string $expression): string
    {
        return $this->dialect === 'sqlite' ? "max(0, $expression)" : "GREATEST(0, $expression)";
    }

    /**
     * The generation number, its row locked until the end of the transaction
     * on the dialects that have row locks. On SQLite the transaction holds
     * the whole database.
     */
    private function lockGeneration(): int
    {
        $statement = $this->pdo->query("SELECT value FROM {$this->meta} WHERE name = 'generation'" . $this->forUpdate());
        if ($statement === false) {
            throw new \RuntimeException('Cannot read the generation');
        }

        return (int) $statement->fetchColumn();
    }

    /**
     * Every row of the key/value table, locked until the end of the
     * transaction when $lock is set and the dialect has row locks.
     *
     * @return array<key-of<self::META>, int>
     */
    private function fetchMeta(bool $lock = false): array
    {
        $statement = $this->pdo->query("SELECT name, value FROM {$this->meta}" . ($lock ? $this->forUpdate() : ''));
        if ($statement === false) {
            throw new \RuntimeException('Cannot read the metadata');
        }

        $meta = self::META;
        foreach ($statement->fetchAll(PDO::FETCH_KEY_PAIR) as $name => $value) {
            if (array_key_exists($name, $meta)) {
                $meta[$name] = (int) $value;
            }
        }

        return $meta;
    }

    /**
     * @return array<key-of<self::META>, int>
     */
    private function readMeta(): array
    {
        if ($this->meta_ !== null) {
            return $this->meta_;
        }

        $meta = $this->fetchMeta();

        if ($meta['bits'] === 0) {
            throw new \RuntimeException('The storage is not installed, call install() first');
        }
        if ($meta['schema'] !== self::SCHEMA) {
            throw new \RuntimeException(sprintf(
                'The storage tables follow schema %d, this library expects schema %d: '
                . 'the tables have to be migrated',
                $meta['schema'],
                self::SCHEMA,
            ));
        }
        if ($meta['hash'] !== FeatureHasher::VERSION) {
            throw new \RuntimeException(sprintf(
                'The storage holds counts for feature hash version %d, this library uses version %d: '
                . 'the site layer has to be relearned',
                $meta['hash'],
                FeatureHasher::VERSION,
            ));
        }

        return $this->meta_ = $meta;
    }
}
