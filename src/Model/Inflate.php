<?php

declare(strict_types=1);

// SPDX-License-Identifier: AGPL-3.0-or-later

namespace Gecka\SpamFilter\Model;

/**
 * Decompresses a zlib stream in slices and stops as soon as the output
 * passes a ceiling, so a small file claiming a huge table never gets the
 * memory it asks for.
 *
 * @author Laurent Dinclaux <laurent@gecka.nc>
 * @copyright Gecka <contact@gecka.nc>
 * @license AGPL-3.0-or-later
 */
final class Inflate
{
    private const SLICE = 65536;

    /**
     * @return string|null The inflated bytes, or null when the stream is not zlib or inflates past $limit
     */
    public static function upTo(string $compressed, int $limit): ?string
    {
        $context = @inflate_init(ZLIB_ENCODING_DEFLATE);
        if ($context === false) {
            return null;
        }

        $output = '';
        $length = strlen($compressed);
        for ($offset = 0; $offset < $length; $offset += self::SLICE) {
            $piece = @inflate_add($context, substr($compressed, $offset, self::SLICE), ZLIB_NO_FLUSH);
            if ($piece === false) {
                return null;
            }
            $output .= $piece;
            if (strlen($output) > $limit) {
                return null;
            }
        }

        $tail = @inflate_add($context, '', ZLIB_FINISH);
        if ($tail === false) {
            return null;
        }
        $output .= $tail;

        return strlen($output) > $limit ? null : $output;
    }
}
