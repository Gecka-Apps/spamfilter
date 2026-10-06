<?php

declare(strict_types=1);

// SPDX-License-Identifier: AGPL-3.0-or-later

namespace Gecka\SpamFilter;

/**
 * The two classes a text can belong to.
 *
 * @author Laurent Dinclaux <laurent@gecka.nc>
 * @copyright Gecka <contact@gecka.nc>
 * @license AGPL-3.0-or-later
 */
enum Label: string
{
    case Ham = 'ham';
    case Spam = 'spam';

    /**
     * Builds a label from the 0/1 convention used by most public corpora.
     */
    public static function fromBinary(int|string $value): self
    {
        return (int) $value === 1 ? self::Spam : self::Ham;
    }

    /**
     * True for the spam class.
     */
    public function isSpam(): bool
    {
        return $this === self::Spam;
    }
}
