<?php

declare(strict_types=1);

// SPDX-License-Identifier: AGPL-3.0-or-later

use Gecka\SpamFilter\Generation;
use Gecka\SpamFilter\Label;
use Gecka\SpamFilter\Model\ClassCounts;
use Gecka\SpamFilter\Storage\Storage;
use Gecka\SpamFilter\Storage\Tally;
use Gecka\SpamFilter\Testing\StorageContract;
use Gecka\SpamFilter\Testing\StorageContractViolation;

/**
 * A correct in-memory storage, with switches to break one rule at a time.
 */
final class FakeStorage implements Storage
{
    private ClassCounts $recent;

    private ClassCounts $archive;

    private int $version = 0;

    private int $generation = 0;

    /** @var array{spam: int, ham: int} */
    private array $learned = ['spam' => 0, 'ham' => 0];

    private readonly string $identity;

    public function __construct(
        private readonly int $bits,
        public bool $replaceInsteadOfAdd = false,
        public bool $allowNegative = false,
        public bool $frozenVersion = false,
        public bool $roundsUp = false,
        public bool $halvesRecentToo = false,
        public bool $staleGeneration = false,
    ) {
        $this->recent = new ClassCounts($bits);
        $this->archive = new ClassCounts($bits);
        $this->identity = 'fake:' . bin2hex(random_bytes(8));
    }

    public function identity(): string
    {
        return $this->identity;
    }

    public function load(): ClassCounts
    {
        return $this->archive->plus($this->recent);
    }

    public function apply(array $hashed, Label $label, int $sign, Generation $generation = Generation::Recent): int
    {
        $counts = $generation === Generation::Recent ? $this->recent : $this->archive;

        if ($this->replaceInsteadOfAdd) {
            $fresh = new ClassCounts($this->bits);
            $fresh->learn($hashed, $label);
            $counts = $fresh;
        } elseif ($this->allowNegative && $sign < 0) {
            // Pretend the counter went negative by over-subtracting on the way back
            $counts->unlearn($hashed, $label);
            $counts->unlearn($hashed, $label);
        } elseif ($sign > 0) {
            $counts->learn($hashed, $label);
        } else {
            $counts->unlearn($hashed, $label);
        }

        if ($generation === Generation::Recent) {
            $this->recent = $counts;
        } else {
            $this->archive = $counts;
        }

        $this->learned[$label->value] = max(0, $this->learned[$label->value] + $sign);

        if (! $this->frozenVersion) {
            $this->version++;
        }

        return $this->staleGeneration ? $this->generation - 1 : $this->generation;
    }

    public function rotate(): void
    {
        if ($this->roundsUp) {
            // Every odd counter gains one before the division
            $copy = new ClassCounts($this->bits);
            foreach ([Label::Spam, Label::Ham] as $label) {
                for ($i = 0; $i < (1 << $this->bits); $i++) {
                    $n = $this->archive->count($label, $i);
                    if ($n > 0) {
                        $copy->learn([$i => intdiv($n + 1, 2)], $label);
                    }
                }
            }
            $this->archive = $copy;
        } else {
            $this->archive->halve();
        }

        if ($this->halvesRecentToo) {
            $this->recent->halve();
        }

        $this->archive = $this->archive->plus($this->recent);
        $this->recent = new ClassCounts($this->bits);
        $this->generation++;
        $this->version++;
    }

    public function tally(): Tally
    {
        return new Tally($this->generation, $this->recent->texts(Label::Spam), $this->recent->texts(Label::Ham), $this->learned['spam'], $this->learned['ham']);
    }

    public function version(): int
    {
        return $this->version;
    }
}

it('accepts a correct storage', function (): void {
    StorageContract::verify(fn(int $bits) => new FakeStorage($bits));
})->throwsNoExceptions();

it('rejects a storage that replaces counts instead of adding', function (): void {
    expect(fn() => StorageContract::verify(fn(int $bits) => new FakeStorage($bits, replaceInsteadOfAdd: true)))
        ->toThrow(StorageContractViolation::class, 'add to an existing counter');
});

it('rejects a storage whose version never moves', function (): void {
    expect(fn() => StorageContract::verify(fn(int $bits) => new FakeStorage($bits, frozenVersion: true)))
        ->toThrow(StorageContractViolation::class, 'version()');
});

it('rejects a storage that rounds up when it halves the archive', function (): void {
    expect(fn() => StorageContract::verify(fn(int $bits) => new FakeStorage($bits, roundsUp: true)))
        ->toThrow(StorageContractViolation::class, 'rounding down');
});

it('rejects a storage that halves the recent generation at rotation', function (): void {
    expect(fn() => StorageContract::verify(fn(int $bits) => new FakeStorage($bits, halvesRecentToo: true)))
        ->toThrow(StorageContractViolation::class, 'add the recent counters');
});

it('rejects a storage whose apply() reports a generation it did not write under', function (): void {
    expect(fn() => StorageContract::verify(fn(int $bits) => new FakeStorage($bits, staleGeneration: true)))
        ->toThrow(StorageContractViolation::class, 'return the generation');
});

it('rejects a storage installed with another feature space', function (): void {
    expect(fn() => StorageContract::verify(fn(int $bits) => new FakeStorage($bits + 1)))
        ->toThrow(StorageContractViolation::class, 'feature space');
});
