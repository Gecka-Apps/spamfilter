<?php

declare(strict_types=1);

// SPDX-License-Identifier: AGPL-3.0-or-later

namespace Gecka\SpamFilter\Model;

use Gecka\SpamFilter\Tokenizer\FeatureHasher;

/**
 * Reads and writes background tables: the frequency of every feature in
 * ordinary text of one language, which the estimator uses to tell a common
 * word from a rare one before the site has learned anything legitimate.
 *
 * Tables are published by the spamfilter-backgrounds project, one file per
 * language (fr.bin, en.bin...), and downloaded with BackgroundDownloader or
 * bin/spamfilter-background into a directory of the application.
 *
 * @author Laurent Dinclaux <laurent@gecka.nc>
 * @copyright Gecka <contact@gecka.nc>
 * @license AGPL-3.0-or-later
 */
final class Background
{
    private const MAGIC = "GSFB\x02";

    // hash version, bits, total
    private const HEADER = 'Chash/Cbits/Jtotal';

    private const HEADER_BYTES = 10;

    /**
     * Loads the *.bin tables of a directory, keyed by file name. A single file
     * loads as a one-language background.
     *
     * With $apcu, each table is kept in APCu after its first decompression
     * and re-read only when the file changes. APCu is shared by every script
     * of the PHP process pool, so this is for a pool that serves one site.
     *
     * @param list<string>|null $languages Codes to load; null loads every table present. Each table costs 4 MB of memory, so load the languages the site actually receives.
     * @param bool $apcu Keep the decompressed tables in APCu
     */
    public static function load(string $path, ?array $languages = null, bool $apcu = false): LanguageBackground
    {
        if (is_file($path)) {
            return new LanguageBackground([pathinfo($path, PATHINFO_FILENAME) => $apcu ? self::cached($path) : self::read($path)]);
        }

        $files = glob(rtrim($path, '/') . '/*.bin') ?: [];
        sort($files);

        $tables = [];
        foreach ($files as $file) {
            $code = pathinfo($file, PATHINFO_FILENAME);
            if ($languages === null || in_array($code, $languages, true)) {
                $tables[$code] = $apcu ? self::cached($file) : self::read($file);
            }
        }

        if ($tables === []) {
            throw new \RuntimeException(
                "No background table in $path" . ($languages !== null ? ' for ' . implode(', ', $languages) : '')
                . '; download some with vendor/bin/spamfilter-background',
            );
        }

        return new LanguageBackground($tables);
    }

    /**
     * Reads one table from a file written by write().
     */
    public static function read(string $path): CountTable
    {
        $binary = file_get_contents($path);
        if ($binary === false) {
            throw new \RuntimeException("Cannot read background table $path");
        }

        return self::fromBinary($binary);
    }

    /**
     * Writes one table to a file, creating its directory when needed.
     */
    public static function write(CountTable $table, string $path): void
    {
        $directory = dirname($path);
        if (! is_dir($directory) && ! mkdir($directory, 0755, true)) {
            throw new \RuntimeException("Cannot create $directory");
        }
        if (file_put_contents($path, self::toBinary($table)) === false) {
            throw new \RuntimeException("Cannot write background table $path");
        }
    }

    /**
     * Decodes a compressed table, refusing anything that is not one, claims more
     * slots than the ceiling or was hashed with another feature hash version.
     */
    public static function fromBinary(string $binary): CountTable
    {
        // Inflation stops at the largest table accepted, whatever the stream claims
        $limit = strlen(self::MAGIC) + self::HEADER_BYTES + (1 << CountTable::MAX_BITS) * 4;
        $data = Inflate::upTo($binary, $limit);
        if ($data === null || strlen($data) < strlen(self::MAGIC) + self::HEADER_BYTES || ! str_starts_with($data, self::MAGIC)) {
            throw new \InvalidArgumentException('Not a spamfilter background table');
        }

        /** @var array{hash: int, bits: int, total: int} $header */
        $header = unpack(self::HEADER, $data, strlen(self::MAGIC));
        if ($header['hash'] !== FeatureHasher::VERSION) {
            throw new \InvalidArgumentException(sprintf(
                'This background table was built with feature hash version %d, this library uses version %d',
                $header['hash'],
                FeatureHasher::VERSION,
            ));
        }
        if ($header['bits'] < 1 || $header['bits'] > CountTable::MAX_BITS) {
            throw new \InvalidArgumentException("Refusing a background table of 2^{$header['bits']} slots");
        }
        $offset = strlen(self::MAGIC) + self::HEADER_BYTES;
        $tableBytes = (1 << $header['bits']) * 4;
        if (strlen($data) !== $offset + $tableBytes) {
            throw new \InvalidArgumentException('Truncated or padded background table');
        }

        return CountTable::fromBinary(substr($data, $offset, $tableBytes), $header['total']);
    }

    /**
     * Encodes a table into its compressed file form.
     */
    public static function toBinary(CountTable $table): string
    {
        $compressed = gzcompress(
            self::MAGIC . pack('CCJ', FeatureHasher::VERSION, $table->bits(), $table->total()) . $table->toBinary(),
            9,
        );
        if ($compressed === false) {
            throw new \RuntimeException('Could not compress the background table');
        }

        return $compressed;
    }

    /**
     * Reads a table through APCu, keyed by path and modification time, or
     * straight from the file when the extension is missing.
     */
    private static function cached(string $path): CountTable
    {
        if (! function_exists('apcu_fetch') || ! function_exists('apcu_store')) {
            return self::read($path);
        }

        $key = 'gecka.spamfilter.background:' . $path . ':' . (string) filemtime($path);
        $cached = apcu_fetch($key);
        if (is_array($cached) && isset($cached['data'], $cached['total'])) {
            return CountTable::fromBinary($cached['data'], $cached['total']);
        }

        $table = self::read($path);
        apcu_store($key, ['data' => $table->toBinary(), 'total' => $table->total()]);

        return $table;
    }
}
