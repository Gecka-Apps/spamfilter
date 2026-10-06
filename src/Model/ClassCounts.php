<?php

declare(strict_types=1);

// SPDX-License-Identifier: AGPL-3.0-or-later

namespace Gecka\SpamFilter\Model;

use Gecka\SpamFilter\Label;
use Gecka\SpamFilter\Tokenizer\FeatureHasher;

/**
 * Everything one layer of the model knows: a feature count table per class,
 * and how many texts each class was learned from.
 *
 * Learning and unlearning are exact inverses, so a text learned by mistake
 * leaves no trace once unlearned.
 *
 * @author Laurent Dinclaux <laurent@gecka.nc>
 * @copyright Gecka <contact@gecka.nc>
 * @license AGPL-3.0-or-later
 */
final class ClassCounts
{
    private const MAGIC = "GSFC\x03";

    // hash version, bits, spam texts, ham texts, spam total, ham total
    private const HEADER = 'Chash/Cbits/Nspam/Nham/JspamTotal/JhamTotal';

    private const HEADER_BYTES = 26;

    private CountTable $spam;

    private CountTable $ham;

    private int $spamTexts = 0;

    private int $hamTexts = 0;

    /**
     * @param int $bits Log2 of the number of slots in each class table
     */
    public function __construct(public readonly int $bits)
    {
        $size = 1 << $bits;
        $this->spam = new CountTable($size);
        $this->ham = new CountTable($size);
    }

    /**
     * Rebuilds a layer from stored rows, as a storage backend does on load.
     *
     * @param iterable<array{0: int, 1: int, 2: int}> $rows feature index, ham count, spam count
     */
    public static function fromRows(int $bits, iterable $rows, int $spamTexts, int $hamTexts): self
    {
        $counts = new self($bits);
        foreach ($rows as [$index, $ham, $spam]) {
            if ($ham > 0) {
                $counts->ham->add($index, $ham);
            }
            if ($spam > 0) {
                $counts->spam->add($index, $spam);
            }
        }
        $counts->spamTexts = $spamTexts;
        $counts->hamTexts = $hamTexts;

        return $counts;
    }

    /**
     * Accepts both the compressed form written by toBinary() and the raw form
     * written by toBinary(false).
     */
    public static function fromBinary(string $binary): self
    {
        // Inflation stops at the largest model this class accepts, whatever
        // the stream claims
        $limit = strlen(self::MAGIC) + self::HEADER_BYTES + 2 * (1 << CountTable::MAX_BITS) * 4;
        $data = str_starts_with($binary, self::MAGIC) ? $binary : Inflate::upTo($binary, $limit);
        if ($data === null || strlen($data) < strlen(self::MAGIC) + self::HEADER_BYTES || ! str_starts_with($data, self::MAGIC)) {
            throw new \InvalidArgumentException('Not a spamfilter model');
        }

        /** @var array{hash: int, bits: int, spam: int, ham: int, spamTotal: int, hamTotal: int} $header */
        $header = unpack(self::HEADER, $data, strlen(self::MAGIC));
        if ($header['hash'] !== FeatureHasher::VERSION) {
            throw new \InvalidArgumentException(sprintf(
                'This model was built with feature hash version %d, this library uses version %d',
                $header['hash'],
                FeatureHasher::VERSION,
            ));
        }
        if ($header['bits'] < 1 || $header['bits'] > CountTable::MAX_BITS) {
            throw new \InvalidArgumentException("Refusing a model of 2^{$header['bits']} slots");
        }
        $offset = strlen(self::MAGIC) + self::HEADER_BYTES;
        $tableBytes = (1 << $header['bits']) * 4;
        if (strlen($data) !== $offset + 2 * $tableBytes) {
            throw new \InvalidArgumentException('Truncated or padded model');
        }

        $counts = new self($header['bits']);
        $counts->spamTexts = $header['spam'];
        $counts->hamTexts = $header['ham'];
        $counts->spam = CountTable::fromBinary(substr($data, $offset, $tableBytes), $header['spamTotal']);
        $counts->ham = CountTable::fromBinary(substr($data, $offset + $tableBytes, $tableBytes), $header['hamTotal']);

        return $counts;
    }

    /**
     * Snapshot of the layer. Compressed, an empty or sparse model shrinks to a
     * few kilobytes; raw, it loads without decompressing, which suits a
     * shared-memory cache.
     */
    public function toBinary(bool $compress = true): string
    {
        $data = self::MAGIC
            . pack('CCNNJJ', FeatureHasher::VERSION, $this->bits, $this->spamTexts, $this->hamTexts, $this->spam->total(), $this->ham->total())
            . $this->spam->toBinary()
            . $this->ham->toBinary();

        if (! $compress) {
            return $data;
        }

        $compressed = gzcompress($data, 6);
        if ($compressed === false) {
            throw new \RuntimeException('Could not compress the model');
        }

        return $compressed;
    }

    /**
     * @param array<int, int> $hashed Feature index => count
     */
    public function learn(array $hashed, Label $label): void
    {
        $this->apply($hashed, $label, 1);
    }

    /**
     * @param array<int, int> $hashed Feature index => count
     */
    public function unlearn(array $hashed, Label $label): void
    {
        $this->apply($hashed, $label, -1);
    }

    /**
     * Halves every counter and both text counts, rounding down. Learning
     * after that is still exact; unlearning a text learned before it is not.
     */
    public function halve(): void
    {
        $this->spam->halve();
        $this->ham->halve();
        $this->spamTexts >>= 1;
        $this->hamTexts >>= 1;
    }

    /**
     * A new layer holding the counters and text counts of this one and
     * $other added together, as a storage with two generations loads them.
     */
    public function plus(self $other): self
    {
        if ($other->bits !== $this->bits) {
            throw new \InvalidArgumentException('Only layers of the same feature space add up');
        }

        $sum = new self($this->bits);
        $sum->spam = $this->spam->plus($other->spam);
        $sum->ham = $this->ham->plus($other->ham);
        $sum->spamTexts = $this->spamTexts + $other->spamTexts;
        $sum->hamTexts = $this->hamTexts + $other->hamTexts;

        return $sum;
    }

    /**
     * The count table of one class.
     */
    public function table(Label $label): CountTable
    {
        return $label->isSpam() ? $this->spam : $this->ham;
    }

    /**
     * Count of one feature slot in a class.
     */
    public function count(Label $label, int $index): int
    {
        return $this->table($label)->get($index);
    }

    /**
     * Sum of all feature counts learned for the class.
     */
    public function total(Label $label): int
    {
        return $this->table($label)->total();
    }

    /**
     * Number of texts learned for the class.
     */
    public function texts(Label $label): int
    {
        return $label->isSpam() ? $this->spamTexts : $this->hamTexts;
    }

    /**
     * Both classes added together: the feature distribution of everything
     * learned, usable as a background table.
     */
    public function marginal(): CountTable
    {
        $spam = unpack('N*', $this->spam->toBinary()) ?: [];
        $ham = unpack('N*', $this->ham->toBinary()) ?: [];

        $sum = '';
        foreach ($spam as $i => $count) {
            $sum .= pack('N', min(0xFFFFFFFF, $count + $ham[$i]));
        }

        return CountTable::fromBinary($sum);
    }

    /**
     * @param array<int, int> $hashed
     */
    private function apply(array $hashed, Label $label, int $sign): void
    {
        $table = $this->table($label);
        foreach ($hashed as $index => $count) {
            $table->add($index, $sign * $count);
        }

        if ($label->isSpam()) {
            $this->spamTexts = max(0, $this->spamTexts + $sign);
        } else {
            $this->hamTexts = max(0, $this->hamTexts + $sign);
        }
    }
}
