<?php

declare(strict_types=1);

// SPDX-License-Identifier: AGPL-3.0-or-later

namespace Gecka\SpamFilter\Storage;

use Gecka\SpamFilter\Model\ClassCounts;

/**
 * Keeps the site snapshot in a file between requests, rebuilding it from the
 * storage only when the storage version has moved.
 *
 * The file is written with $mode, 0600 by default, in a directory created
 * with the same mode plus the search bits, so on a host where PHP runs under
 * the site's own user nothing else reads or replaces it, which APCu cannot
 * promise on a shared process pool. With $strict, a file that belongs to
 * another user or carries permission bits beyond $mode is not trusted: it is
 * ignored and replaced. A deployment where a cron user and php-fpm share a
 * group passes a group mode and turns the check off. The write goes to a
 * temporary name in the same directory and is renamed into place, so a
 * reader never sees a partial file; a symbolic link in place of the file is
 * ignored and replaced whatever the settings.
 *
 * @author Laurent Dinclaux <laurent@gecka.nc>
 * @copyright Gecka <contact@gecka.nc>
 * @license AGPL-3.0-or-later
 */
final class FileSnapshotCache
{
    /**
     * The file opens with the storage version and a hash of the storage
     * identity, 8 bytes each. Both must match for the file to be served:
     * the version catches a change in the counters, the identity a file
     * written for other tables, as after a reinstall or when two sites
     * share one path by mistake.
     */
    private const HEADER_BYTES = 16;

    /**
     * @param Storage $storage Where the snapshot is rebuilt from when the file is stale
     * @param string $path The snapshot file, in a directory of the site, created when missing
     * @param int $mode Permission bits of the file; the directory gets them plus the matching search bits
     * @param bool $strict Refuse a file of another user or with bits beyond $mode
     */
    public function __construct(
        private readonly Storage $storage,
        private readonly string $path,
        private readonly int $mode = 0600,
        private readonly bool $strict = true,
    ) {
        if (($mode & ~0777) !== 0 || ($mode & 0600) !== 0600) {
            throw new \InvalidArgumentException('mode must be permission bits readable and writable by the owner, such as 0600 or 0660');
        }
    }

    /**
     * The site layer, from the file when its header matches the storage's
     * version and identity, from the storage otherwise.
     */
    public function load(): ClassCounts
    {
        $header = pack('J', $this->storage->version()) . hash('xxh3', $this->storage->identity(), true);

        $cached = $this->read($header);
        if ($cached !== null) {
            return $cached;
        }

        $counts = $this->storage->load();
        $this->write($header, $counts);

        return $counts;
    }

    private function read(string $header): ?ClassCounts
    {
        if (! $this->trusted()) {
            return null;
        }

        $data = file_get_contents($this->path);
        if ($data === false || strlen($data) <= self::HEADER_BYTES || ! hash_equals($header, substr($data, 0, self::HEADER_BYTES))) {
            return null;
        }

        try {
            return ClassCounts::fromBinary(substr($data, self::HEADER_BYTES));
        } catch (\InvalidArgumentException) {
            return null;
        }
    }

    /**
     * Whether the file is a readable regular file and, with $strict, one of
     * the current user with no permission bits beyond $mode.
     */
    private function trusted(): bool
    {
        clearstatcache(true, $this->path);
        if (! is_file($this->path) || is_link($this->path) || ! is_readable($this->path)) {
            return false;
        }
        if (! $this->strict) {
            return true;
        }

        $owner = fileowner($this->path);
        $bits = fileperms($this->path);
        $self = function_exists('posix_geteuid') ? posix_geteuid() : getmyuid();

        return $owner !== false && $bits !== false && $owner === $self && ($bits & 0777 & ~$this->mode) === 0;
    }

    private function write(string $header, ClassCounts $counts): void
    {
        $directory = dirname($this->path);
        $directoryMode = $this->mode | (($this->mode & 0444) >> 2);
        if (! is_dir($directory)) {
            if (! mkdir($directory, $directoryMode, true) && ! is_dir($directory)) {
                throw new \RuntimeException("Cannot create $directory");
            }
            // mkdir() applies the umask, chmod() does not
            chmod($directory, $directoryMode);
        }

        $temporary = $this->path . '.' . bin2hex(random_bytes(6)) . '.part';
        if (file_put_contents($temporary, $header . $counts->toBinary(false)) === false) {
            throw new \RuntimeException("Cannot write $temporary");
        }
        chmod($temporary, $this->mode);
        if (! rename($temporary, $this->path)) {
            unlink($temporary);
            throw new \RuntimeException("Cannot move the snapshot into {$this->path}");
        }
    }
}
