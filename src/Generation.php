<?php

declare(strict_types=1);

// SPDX-License-Identifier: AGPL-3.0-or-later

namespace Gecka\SpamFilter;

/**
 * Where the counts of a learned text go. Recent counts keep their full
 * weight; at each rotation the archive is halved and the recent counts move
 * into it, so a text weighs half as much with every rotation it outlives
 * past the first.
 *
 * @author Laurent Dinclaux <laurent@gecka.nc>
 * @copyright Gecka <contact@gecka.nc>
 * @license AGPL-3.0-or-later
 */
enum Generation
{
    case Recent;
    case Archive;
}
