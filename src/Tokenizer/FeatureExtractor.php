<?php

declare(strict_types=1);

// SPDX-License-Identifier: AGPL-3.0-or-later

namespace Gecka\SpamFilter\Tokenizer;

/**
 * Turns a text into a bag of readable features with their counts.
 *
 * Each feature carries a short prefix naming its family, so that a word, a
 * character n-gram and a host name can never collide once hashed:
 *
 *   w:bonjour        a word, lower-cased and NFKC-normalised
 *   w2:devis_gratuit two consecutive words
 *   c3:_bo c4:_bon   character n-grams over a word padded with "_"
 *   num:4            a run of digits, bucketed by length
 *   url: host:x.com tld:com   links and their parts
 *   mail:gmail.com   e-mail address domain
 *   tag:a            an HTML tag
 *   caps:            a word written in capitals
 *   punct:!          exclamation marks, one feature per occurrence
 *   sym:€            currency symbols
 *   pcre:            a regular expression gave up on the text (PCRE limits)
 *
 * Words and n-grams are measured in characters, not bytes, so the limits mean
 * the same thing for Latin, Cyrillic and CJK scripts.
 *
 * Every regular expression runs under the PCRE backtracking and JIT stack
 * limits of the PHP configuration. When one gives up, the text keeps its
 * other features and gets the pcre: marker, so a text built to defeat the
 * extractor stands out instead of slipping through with fewer features.
 *
 * @author Laurent Dinclaux <laurent@gecka.nc>
 * @copyright Gecka <contact@gecka.nc>
 * @license AGPL-3.0-or-later
 */
final class FeatureExtractor
{
    // Either an explicit link, or a bare domain: lower-case labels, a short
    // suffix and a word boundary after it, so "merci.Cordialement" is not one
    private const URL_PATTERN = '~(?:https?://|www\.)[^\s<>"\'()\[\]]+|(?-i:(?<![\w@.-])[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)*\.[a-z]{2,10}(?=$|[\s.,;:!?)\]"\'<>/])(?:/[^\s<>"\'()\[\]]*)?)~iu';

    private const CLAUSE_SPLIT = '~[.,;:!?()\[\]{}"«»\r\n]+~u';

    private const MAIL_PATTERN = '~[\w.+-]+@([a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+)~iu';

    private const TAG_PATTERN = '~<\s*/?\s*([a-z][a-z0-9]*)(?=[\s/>])[^>]*>~iu';

    // Only these names make a tag; "< n and n >" or "<john@example.com>" stay text
    private const HTML_ELEMENTS = [
        'a', 'abbr', 'address', 'area', 'article', 'aside', 'audio', 'b', 'base', 'bdi', 'bdo', 'blockquote', 'body',
        'br', 'button', 'canvas', 'caption', 'center', 'cite', 'code', 'col', 'colgroup', 'data', 'datalist', 'dd',
        'del', 'details', 'dfn', 'dialog', 'div', 'dl', 'dt', 'em', 'embed', 'fieldset', 'figcaption', 'figure',
        'font', 'footer', 'form', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'head', 'header', 'hgroup', 'hr', 'html', 'i',
        'iframe', 'img', 'input', 'ins', 'kbd', 'label', 'legend', 'li', 'link', 'main', 'map', 'mark', 'marquee',
        'menu', 'meta', 'meter', 'nav', 'noscript', 'object', 'ol', 'optgroup', 'option', 'output', 'p', 'param',
        'picture', 'pre', 'progress', 'q', 'rp', 'rt', 'ruby', 's', 'samp', 'script', 'section', 'select', 'slot',
        'small', 'source', 'span', 'strike', 'strong', 'style', 'sub', 'summary', 'sup', 'table', 'tbody', 'td',
        'template', 'textarea', 'tfoot', 'th', 'thead', 'time', 'title', 'tr', 'track', 'tt', 'u', 'ul', 'var',
        'video', 'wbr',
    ];

    private const WORD_SPLIT = '~[^\p{L}\p{N}]+~u';

    private const INVISIBLE = '~[\x{200B}-\x{200F}\x{FEFF}\x{00AD}]~u';

    // Scripts written without spaces between words
    private const UNSPACED = '~[\p{Han}\p{Hiragana}\p{Katakana}\p{Thai}\p{Khmer}\p{Lao}\p{Myanmar}]~u';

    /**
     * @param int $minWordLength Shorter words are dropped (characters)
     * @param int $maxWordLength Longer words are kept only through their character n-grams
     * @param CharNgrams $charNgrams Which words get character n-grams
     * @param int $minNgram Smallest character n-gram
     * @param int $maxNgram Largest character n-gram
     * @param bool $wordBigrams Emit pairs of consecutive words
     */
    public function __construct(
        private readonly int $minWordLength = 2,
        private readonly int $maxWordLength = 40,
        private readonly CharNgrams $charNgrams = CharNgrams::Unspaced,
        private readonly int $minNgram = 2,
        private readonly int $maxNgram = 4,
        private readonly bool $wordBigrams = true,
    ) {}

    /**
     * @return array<string, int> Feature => number of occurrences
     */
    public function extract(string $text): array
    {
        $features = [];
        $add = static function (string $feature) use (&$features): void {
            $features[$feature] = ($features[$feature] ?? 0) + 1;
        };

        $text = html_entity_decode($text, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $text = self::guarded(preg_replace(self::INVISIBLE, '', $text), $text, $add);

        // Links, addresses and markup are taken out first so their inner parts
        // are not split into ordinary words a second time. Links go first: a
        // link may carry an address ("http://user@host/path") and both may sit
        // between angle brackets, where a tag would otherwise swallow them
        $text = $this->extractUrls($text, $add);
        $text = $this->extractMails($text, $add);
        $text = $this->extractTags($text, $add);

        $this->extractSymbols($text, $add);

        $normalized = normalizer_normalize($text, \Normalizer::FORM_KC);
        if ($normalized === false) {
            $normalized = $text;
        }

        $this->extractWords($normalized, $add);

        return $features;
    }

    /**
     * @param callable(string): void $add
     */
    private function extractTags(string $text, callable $add): string
    {
        return self::guarded(preg_replace_callback(self::TAG_PATTERN, static function (array $m) use ($add): string {
            $name = strtolower($m[1]);
            if (! in_array($name, self::HTML_ELEMENTS, true)) {
                return $m[0];
            }
            $add('tag:' . $name);

            return ' ';
        }, $text), $text, $add);
    }

    /**
     * @param callable(string): void $add
     */
    private function extractMails(string $text, callable $add): string
    {
        return self::guarded(preg_replace_callback(self::MAIL_PATTERN, static function (array $m) use ($add): string {
            $add('mail:');
            $add('mail:' . strtolower($m[1]));

            return ' ';
        }, $text), $text, $add);
    }

    /**
     * The link itself counts once, then its host, its public suffix and the
     * words of its path are added, so a new URL on a known spammy host still
     * carries weight.
     *
     * @param callable(string): void $add
     */
    private function extractUrls(string $text, callable $add): string
    {
        return self::guarded(preg_replace_callback(self::URL_PATTERN, function (array $m) use ($add): string {
            $url = rtrim($m[0], '.,;:!?');
            $withScheme = preg_match('~^[a-z][a-z0-9+.-]*://~i', $url) === 1 ? $url : 'http://' . $url;
            $host = parse_url($withScheme, PHP_URL_HOST);
            $path = parse_url($withScheme, PHP_URL_PATH);

            $add('url:');
            if (is_string($host)) {
                $host = strtolower(preg_replace('~^www\.~', '', $host) ?? $host);
                $add('host:' . $host);
                $labels = explode('.', $host);
                $add('tld:' . end($labels));
            }
            if (is_string($path) && $path !== '' && $path !== '/') {
                foreach ($this->splitWords(strtolower($path), $add) as $word) {
                    $add('path:' . $word);
                }
            }

            return ' ';
        }, $text), $text, $add);
    }

    /**
     * The result of a regular expression, or the untouched text with the
     * pcre: marker when PCRE gave up on it.
     *
     * @param callable(string): void $add
     */
    private static function guarded(?string $result, string $text, callable $add): string
    {
        if ($result === null) {
            $add('pcre:');

            return $text;
        }

        return $result;
    }

    /**
     * @param callable(string): void $add
     */
    private function extractSymbols(string $text, callable $add): void
    {
        $exclamations = substr_count($text, '!');
        for ($i = 0; $i < $exclamations; $i++) {
            $add('punct:!');
        }

        $symbols = preg_match_all('~[€$£¥₹]~u', $text, $m);
        if ($symbols > 0) {
            foreach ($m[0] as $symbol) {
                $add('sym:' . $symbol);
            }
        }
    }

    /**
     * @param callable(string): void $add
     */
    private function extractWords(string $text, callable $add): void
    {
        // Bigrams do not cross a punctuation mark: each clause starts afresh
        $clauses = preg_split(self::CLAUSE_SPLIT, $text, -1, PREG_SPLIT_NO_EMPTY);
        if ($clauses === false) {
            $add('pcre:');
            $clauses = [$text];
        }
        foreach ($clauses as $clause) {
            $this->extractClauseWords($clause, $add);
        }
    }

    /**
     * @param callable(string): void $add
     */
    private function extractClauseWords(string $text, callable $add): void
    {
        $previous = null;

        foreach ($this->splitWords($text, $add) as $raw) {
            $length = mb_strlen($raw);

            if (preg_match('~^\p{N}+$~u', $raw) === 1) {
                $add('num:' . min($length, 12));
                $previous = null;
                continue;
            }

            if ($length >= 3 && $raw === mb_strtoupper($raw) && $raw !== mb_strtolower($raw)) {
                $add('caps:');
            }

            $word = mb_strtolower($raw);

            if ($length >= $this->minWordLength && $length <= $this->maxWordLength) {
                $add('w:' . $word);
                if ($this->wordBigrams && $previous !== null) {
                    $add('w2:' . $previous . '_' . $word);
                }
                $previous = $word;
            } else {
                $previous = null;
            }

            if ($this->wantsCharNgrams($word)) {
                $this->extractCharNgrams($word, $add);
            }
        }
    }

    /**
     * Whether a word gets character n-grams under the configured CharNgrams mode.
     */
    private function wantsCharNgrams(string $word): bool
    {
        return match ($this->charNgrams) {
            CharNgrams::None => false,
            CharNgrams::All => true,
            CharNgrams::Unspaced => preg_match(self::UNSPACED, $word) === 1,
        };
    }

    /**
     * Pads the word with "_" so that prefixes and suffixes are distinct from
     * the same letters inside a word, then slides windows of every requested size.
     *
     * @param callable(string): void $add
     */
    private function extractCharNgrams(string $word, callable $add): void
    {
        $padded = '_' . $word . '_';
        $chars = mb_str_split($padded);
        $count = count($chars);

        for ($n = $this->minNgram; $n <= $this->maxNgram; $n++) {
            if ($count < $n) {
                break;
            }
            for ($i = 0; $i + $n <= $count; $i++) {
                $add('c' . $n . ':' . implode('', array_slice($chars, $i, $n)));
            }
        }
    }

    /**
     * Words of a text, cut on anything that is not a letter or a digit; cut
     * on blanks only when PCRE gives up, so the words still count.
     *
     * @param callable(string): void $add
     * @return list<string>
     */
    private function splitWords(string $text, callable $add): array
    {
        $parts = preg_split(self::WORD_SPLIT, $text, -1, PREG_SPLIT_NO_EMPTY);
        if ($parts === false) {
            $add('pcre:');

            return array_values(array_filter(explode(' ', str_replace(["\n", "\r", "\t"], ' ', $text)), static fn(string $w): bool => $w !== ''));
        }

        return $parts;
    }
}
