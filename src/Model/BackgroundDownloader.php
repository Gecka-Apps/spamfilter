<?php

declare(strict_types=1);

// SPDX-License-Identifier: AGPL-3.0-or-later

namespace Gecka\SpamFilter\Model;

use Gecka\SpamFilter\Tokenizer\FeatureHasher;

/**
 * Fetches background tables published by the spamfilter-backgrounds project:
 * reads its manifest, downloads the requested languages and checks each file
 * against the manifest's SHA-256 and feature hash version before keeping it.
 *
 * @author Laurent Dinclaux <laurent@gecka.nc>
 * @copyright Gecka <contact@gecka.nc>
 * @license AGPL-3.0-or-later
 */
final class BackgroundDownloader
{
    public const DEFAULT_MANIFEST = 'https://github.com/Gecka-Apps/spamfilter-backgrounds/releases/latest/download/manifest.json';

    public const CHANGED = 'changed';

    public const UNPUBLISHED = 'unpublished';

    /** @var array{hash_version: int, version?: mixed, generated?: mixed, languages: array<string, array<string, mixed>>}|null */
    private ?array $manifest = null;

    /**
     * @param string $manifestUrl Where the manifest of the published tables is fetched from, https or a local file:// copy
     */
    public function __construct(private readonly string $manifestUrl = self::DEFAULT_MANIFEST) {}

    /**
     * The published release, as named by the manifest, when it says.
     */
    public function version(): ?string
    {
        $version = $this->manifest()['version'] ?? null;

        return is_string($version) && $version !== '' ? $version : null;
    }

    /**
     * When the manifest was generated, as the ISO 8601 date it carries.
     */
    public function generated(): ?string
    {
        $generated = $this->manifest()['generated'] ?? null;

        return is_string($generated) && $generated !== '' ? $generated : null;
    }

    /**
     * Languages the manifest offers, code => name.
     *
     * @return array<string, string>
     */
    public function available(): array
    {
        return array_map(static fn(array $entry): string => (string) ($entry['name'] ?? ''), $this->manifest()['languages']);
    }

    /**
     * Tables of a directory that the published release no longer matches:
     * code => CHANGED when the manifest announces another checksum,
     * UNPUBLISHED when the manifest has no table for that language any more.
     * Comparing checksums costs reading each local table once.
     *
     * @return array<string, string>
     */
    public function outdated(string $directory): array
    {
        $manifest = $this->manifest();
        $this->checkHashVersion($manifest['hash_version']);

        $files = glob(rtrim($directory, '/') . '/*.bin') ?: [];
        sort($files);

        $outdated = [];
        foreach ($files as $file) {
            $code = pathinfo($file, PATHINFO_FILENAME);
            $entry = $manifest['languages'][$code] ?? null;
            if ($entry === null) {
                $outdated[$code] = self::UNPUBLISHED;
            } elseif (! is_string($entry['sha256'] ?? null) || hash_file('sha256', $file) !== $entry['sha256']) {
                $outdated[$code] = self::CHANGED;
            }
        }

        return $outdated;
    }

    /**
     * Downloads again the tables of a directory that the release has changed
     * and returns the paths written. Tables no longer published are left as
     * they are.
     *
     * @return list<string>
     */
    public function update(string $directory): array
    {
        $changed = array_keys(array_filter($this->outdated($directory), static fn(string $state): bool => $state === self::CHANGED));

        return $changed === [] ? [] : $this->download($changed, $directory);
    }

    /**
     * How much text each table was built from: code => sentences. A table
     * built from a few hundred sentences says little about its language.
     *
     * @return array<string, int>
     */
    public function sentences(): array
    {
        return array_map(static fn(array $entry): int => (int) ($entry['sentences'] ?? 0), $this->manifest()['languages']);
    }

    /**
     * Downloads the tables for the given language codes into a directory and
     * returns the paths written. An unknown code or a corrupt download throws.
     *
     * @param list<string> $codes
     * @return list<string>
     */
    public function download(array $codes, string $directory): array
    {
        $manifest = $this->manifest();
        $this->checkHashVersion($manifest['hash_version']);

        if (! is_dir($directory) && ! mkdir($directory, 0755, true)) {
            throw new \RuntimeException("Cannot create $directory");
        }

        $written = [];
        foreach ($codes as $code) {
            // The code becomes a file name
            if (preg_match('/^[a-z]{2,3}(?:[-_][a-z0-9]{2,8})?$/', $code) !== 1) {
                throw new \InvalidArgumentException("\"$code\" is not a language code");
            }
            $entry = $manifest['languages'][$code] ?? null;
            if ($entry === null) {
                throw new \InvalidArgumentException("No background table for language \"$code\"; see available()");
            }
            if (! is_string($entry['url']) || ! is_string($entry['sha256']) || ! is_int($entry['bytes'])) {
                throw new \RuntimeException("Malformed manifest entry for \"$code\"");
            }

            $binary = $this->fetch($entry['url'], $entry['bytes']);
            if (hash('sha256', $binary) !== $entry['sha256']) {
                throw new \RuntimeException("The table for \"$code\" does not match its checksum");
            }
            // Parses the header, which also rejects a table of another hash version
            Background::fromBinary($binary);

            // Written next to its final name, then moved, so a request loading the
            // directory never sees a half-written table
            $path = rtrim($directory, '/') . "/$code.bin";
            if (file_put_contents("$path.part", $binary) === false || ! rename("$path.part", $path)) {
                @unlink("$path.part");
                throw new \RuntimeException("Cannot write $path");
            }
            $written[] = $path;
        }

        return $written;
    }

    /**
     * Refuses tables hashed with another feature hash version than this library's.
     */
    private function checkHashVersion(int $published): void
    {
        if ($published !== FeatureHasher::VERSION) {
            throw new \RuntimeException(sprintf(
                'The published tables are built for feature hash version %d, this library uses version %d',
                $published,
                FeatureHasher::VERSION,
            ));
        }
    }

    /**
     * @return array{hash_version: int, version?: mixed, generated?: mixed, languages: array<string, array<string, mixed>>}
     */
    private function manifest(): array
    {
        if ($this->manifest !== null) {
            return $this->manifest;
        }

        $decoded = json_decode($this->fetch($this->manifestUrl), true);
        if (! is_array($decoded) || ! isset($decoded['hash_version'], $decoded['languages']) || ! is_array($decoded['languages'])) {
            throw new \RuntimeException("Malformed background manifest at {$this->manifestUrl}");
        }

        /** @var array{hash_version: int, version?: mixed, generated?: mixed, languages: array<string, array<string, mixed>>} $decoded */
        $this->manifest = $decoded;

        return $decoded;
    }

    /**
     * Reads a URL over https, or over file:// when the manifest itself is a
     * local file, up to $maxBytes (the manifest's figure for a table, a few
     * megabytes for the manifest itself).
     */
    private function fetch(string $url, int $maxBytes = 4 * 1024 * 1024): string
    {
        $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
        $local = str_starts_with(strtolower($this->manifestUrl), 'file://');
        if ($scheme !== 'https' && ! ($local && $scheme === 'file')) {
            throw new \RuntimeException("Refusing to download $url: only https is accepted");
        }

        $context = stream_context_create(['http' => ['timeout' => 120, 'follow_location' => 1, 'user_agent' => 'gecka/spamfilter']]);
        $content = @file_get_contents($url, false, $context, 0, max(0, $maxBytes) + 1);
        if ($content === false) {
            throw new \RuntimeException("Cannot download $url");
        }
        if (strlen($content) > $maxBytes) {
            throw new \RuntimeException("$url is larger than announced");
        }

        return $content;
    }
}
