<?php

declare(strict_types=1);

// SPDX-License-Identifier: AGPL-3.0-or-later

namespace Gecka\SpamFilter\Model;

/**
 * A dense table of unsigned 32-bit counters indexed by hashed feature.
 *
 * The counters live in one binary string of 4 bytes per slot, so a 2^20
 * feature space costs 4 MB whatever the vocabulary, loads with a single read
 * and needs no PHP array overhead. Writes change bytes in place.
 *
 * The size is a power of two and any feature hash is folded into it with a
 * mask, so tables of different sizes can be indexed by the same hash.
 *
 * @author Laurent Dinclaux <laurent@gecka.nc>
 * @copyright Gecka <contact@gecka.nc>
 * @license AGPL-3.0-or-later
 */
final class CountTable
{
    /**
     * Largest feature space accepted: 2^24 slots, 64 MB. A table that claims
     * more is refused rather than allocated, which bounds what a model file
     * or a download can make a process do.
     */
    public const MAX_BITS = 24;

    private const MAX = 0xFFFFFFFF;

    private string $data;

    private int $total = 0;

    private readonly int $mask;

    /**
     * @param int $size Number of slots, a power of two up to 2^MAX_BITS
     */
    public function __construct(public readonly int $size)
    {
        if ($size < 1 || ($size & ($size - 1)) !== 0) {
            throw new \InvalidArgumentException('size must be a power of two');
        }
        if ($size > (1 << self::MAX_BITS)) {
            throw new \InvalidArgumentException('size must not exceed 2^' . self::MAX_BITS);
        }
        $this->mask = $size - 1;
        $this->data = str_repeat("\0", $size * 4);
    }

    /**
     * Log2 of the size.
     */
    public function bits(): int
    {
        return (int) round(log($this->size, 2));
    }

    /**
     * Rebuilds a table from the bytes produced by toBinary(). Passing the
     * known total skips a pass over every slot.
     */
    public static function fromBinary(string $data, ?int $total = null): self
    {
        if (strlen($data) % 4 !== 0 || $data === '') {
            throw new \InvalidArgumentException('Malformed count table');
        }

        $table = new self(intdiv(strlen($data), 4));
        $table->data = $data;

        if ($total === null) {
            $total = 0;
            foreach (unpack('N*', $data) ?: [] as $value) {
                $total += $value;
            }
        }
        $table->total = $total;

        return $table;
    }

    /**
     * The slots as big-endian 32-bit integers, four bytes each.
     */
    public function toBinary(): string
    {
        return $this->data;
    }

    /**
     * @param int $hash Any feature hash; it is folded into the table's size
     */
    public function get(int $hash): int
    {
        /** @var array{1: int} $unpacked */
        $unpacked = unpack('N', $this->data, ($hash & $this->mask) * 4);

        return $unpacked[1];
    }

    /**
     * Adds $by (which may be negative) to a slot, clamped to the uint32 range.
     *
     * @param int $hash Any feature hash; it is folded into the table's size
     */
    public function add(int $hash, int $by): void
    {
        $offset = ($hash & $this->mask) * 4;
        $current = $this->get($hash);
        $value = max(0, min(self::MAX, $current + $by));

        $this->total += $value - $current;

        $this->data[$offset] = chr(($value >> 24) & 0xFF);
        $this->data[$offset + 1] = chr(($value >> 16) & 0xFF);
        $this->data[$offset + 2] = chr(($value >> 8) & 0xFF);
        $this->data[$offset + 3] = chr($value & 0xFF);
    }

    /**
     * Halves every counter, rounding down, so that what was learned long ago
     * weighs less than what comes in now. A count of one becomes zero.
     */
    public function halve(): void
    {
        $halved = '';
        $total = 0;
        foreach (unpack('N*', $this->data) ?: [] as $value) {
            $value >>= 1;
            $total += $value;
            $halved .= pack('N', $value);
        }

        $this->data = $halved;
        $this->total = $total;
    }

    /**
     * A new table holding, slot by slot, the sum of this one and $other,
     * clamped to the uint32 range.
     */
    public function plus(self $other): self
    {
        if ($other->size !== $this->size) {
            throw new \InvalidArgumentException('Only tables of the same size add up');
        }

        $mine = unpack('N*', $this->data) ?: [];
        $theirs = unpack('N*', $other->data) ?: [];

        $sum = '';
        $total = 0;
        foreach ($mine as $i => $count) {
            $value = min(self::MAX, $count + $theirs[$i]);
            $total += $value;
            $sum .= pack('N', $value);
        }

        $table = new self($this->size);
        $table->data = $sum;
        $table->total = $total;

        return $table;
    }

    /**
     * Sum of every counter.
     */
    public function total(): int
    {
        return $this->total;
    }

    /**
     * Number of slots holding a non-zero count.
     */
    public function occupied(): int
    {
        $occupied = 0;
        foreach (unpack('N*', $this->data) ?: [] as $value) {
            if ($value !== 0) {
                $occupied++;
            }
        }

        return $occupied;
    }
}
