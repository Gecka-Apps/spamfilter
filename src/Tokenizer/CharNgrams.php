<?php

declare(strict_types=1);

// SPDX-License-Identifier: AGPL-3.0-or-later

namespace Gecka\SpamFilter\Tokenizer;

/**
 * Which words get character n-grams.
 *
 * In scripts written without spaces (Chinese, Japanese, Thai...) a "word" is
 * a whole phrase and only its n-grams make usable features. In scripts with
 * spaces, n-grams restate the evidence the word already carries and dilute it.
 *
 * @author Laurent Dinclaux <laurent@gecka.nc>
 * @copyright Gecka <contact@gecka.nc>
 * @license AGPL-3.0-or-later
 */
enum CharNgrams
{
    case None;
    case Unspaced;
    case All;
}
