<?php

declare(strict_types=1);

// SPDX-License-Identifier: AGPL-3.0-or-later

namespace Gecka\SpamFilter\Storage;

use Gecka\SpamFilter\Model\ClassCounts;

/**
 * Keeps the site snapshot in APCu between requests, rebuilding it from the
 * storage only when the storage version has moved.
 *
 * The cache key is derived from the storage's identity, so two sites served
 * by one PHP-FPM pool keep separate snapshots. Every script of that pool
 * can read and replace any APCu entry, though, so this cache is for a pool
 * that serves one site; FileSnapshotCache is the choice on a shared pool.
 * Without APCu, every call loads from the storage.
 *
 * @author Laurent Dinclaux <laurent@gecka.nc>
 * @copyright Gecka <contact@gecka.nc>
 * @license AGPL-3.0-or-later
 */
final class SnapshotCache
{
    /**
     * @param Storage $storage Where the snapshot is rebuilt from when the cache is stale
     */
    public function __construct(private readonly Storage $storage) {}

    /**
     * The site layer, from APCu when its version matches the storage's, from the storage otherwise.
     */
    public function load(): ClassCounts
    {
        if (! function_exists('apcu_fetch') || ! function_exists('apcu_store')) {
            return $this->storage->load();
        }

        $key = 'gecka.spamfilter.site:' . hash('xxh3', $this->storage->identity());
        $version = $this->storage->version();
        $cached = apcu_fetch($key);
        if (is_array($cached) && ($cached['version'] ?? null) === $version && is_string($cached['data'] ?? null)) {
            return ClassCounts::fromBinary($cached['data']);
        }

        $counts = $this->storage->load();
        apcu_store($key, ['version' => $version, 'data' => $counts->toBinary(false)]);

        return $counts;
    }
}
