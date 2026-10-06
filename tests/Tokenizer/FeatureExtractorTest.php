<?php

declare(strict_types=1);

// SPDX-License-Identifier: AGPL-3.0-or-later

use Gecka\SpamFilter\Tokenizer\CharNgrams;
use Gecka\SpamFilter\Tokenizer\FeatureExtractor;

/**
 * @return array<string, int>
 */
function features(string $text, FeatureExtractor $extractor = new FeatureExtractor()): array
{
    return $extractor->extract($text);
}

/**
 * @param array<string, int> $features
 * @return list<string>
 */
function keysWithPrefix(array $features, string $prefix): array
{
    return array_values(array_filter(array_keys($features), fn(string $k) => str_starts_with($k, $prefix)));
}

it('lower-cases words and counts repetitions', function (): void {
    $f = features('Bonjour bonjour BONJOUR');

    expect($f['w:bonjour'])->toBe(3);
    expect($f['caps:'])->toBe(1);
});

it('keeps accented words whole and normalises composed forms', function (): void {
    // "e" followed by a combining acute accent is folded to the precomposed "é"
    $f = features("re\u{0301}fe\u{0301}rencement référencement");

    expect($f['w:référencement'])->toBe(2);
});

it('emits bigrams of consecutive words', function (): void {
    $f = features('devis gratuit, devis gratuit');

    expect($f['w2:devis_gratuit'])->toBe(2);
    expect($f)->not->toHaveKey('w2:gratuit_devis');
});

it('does not bridge a bigram over a number', function (): void {
    $f = features('appelez 0612345678 maintenant');

    expect($f['num:10'])->toBe(1);
    expect($f)->not->toHaveKey('w2:appelez_maintenant');
});

it('emits padded character n-grams when asked for every script', function (): void {
    $f = features('seo', new FeatureExtractor(charNgrams: CharNgrams::All, minNgram: 3, maxNgram: 3));

    expect(keysWithPrefix($f, 'c3:'))->toBe(['c3:_se', 'c3:seo', 'c3:eo_']);
    expect($f)->not->toHaveKey('c4:_seo');
});

it('makes an obfuscated word share n-grams with the plain one', function (): void {
    $extractor = new FeatureExtractor(charNgrams: CharNgrams::All, minNgram: 3, maxNgram: 4);
    $plain = features('viagra', $extractor);
    $leet = features('v1agra', $extractor);

    $shared = array_intersect(keysWithPrefix($plain, 'c'), keysWithPrefix($leet, 'c'));

    expect($shared)->toContain('c3:gra', 'c3:ra_', 'c4:gra_', 'c3:agr');
    expect($leet)->not->toHaveKey('w:viagra');
});

it('gives character n-grams to unspaced scripts only by default', function (): void {
    $f = features('免费赚钱 free money', new FeatureExtractor(minNgram: 2, maxNgram: 2));

    expect($f)->toHaveKey('w:免费赚钱');
    expect(keysWithPrefix($f, 'c2:'))->toBe(['c2:_免', 'c2:免费', 'c2:费赚', 'c2:赚钱', 'c2:钱_']);
    expect($f)->toHaveKeys(['w:free', 'w:money']);
});

it('can switch character n-grams off entirely', function (): void {
    $f = features('免费赚钱 free', new FeatureExtractor(charNgrams: CharNgrams::None));

    expect(keysWithPrefix($f, 'c'))->toBe([]);
});

it('extracts links with their host, suffix and path words', function (): void {
    $f = features('Visit https://www.Cheap-Leads.example.com/free-seo-audit?x=1 now.');

    expect($f['url:'])->toBe(1);
    expect($f['host:cheap-leads.example.com'])->toBe(1);
    expect($f['tld:com'])->toBe(1);
    expect($f)->toHaveKeys(['path:free', 'path:seo', 'path:audit']);
    expect($f)->toHaveKeys(['w:visit', 'w:now']);
    expect($f)->not->toHaveKey('w:https');
    expect($f)->not->toHaveKey('w:cheap');
});

it('recognises bare domains and trailing punctuation', function (): void {
    $f = features('Check pimpmyviews.com. Or seo-agency.co.uk!');

    expect($f['host:pimpmyviews.com'])->toBe(1);
    expect($f['host:seo-agency.co.uk'])->toBe(1);
    expect($f['url:'])->toBe(2);
    expect($f['tld:uk'])->toBe(1);
});

it('keeps the domain of an e-mail address and drops the local part', function (): void {
    $f = features('contact me at John.Doe+promo@Gmail.com');

    expect($f['mail:'])->toBe(1);
    expect($f['mail:gmail.com'])->toBe(1);
    expect($f)->not->toHaveKey('w:john');
    expect($f)->not->toHaveKey('host:gmail.com');
});

it('reduces HTML tags to their name', function (): void {
    $f = features('great <a rel="nofollow" href="https://x.example">link</a><br />');

    expect($f['tag:a'])->toBe(2);
    expect($f['tag:br'])->toBe(1);
    expect($f)->not->toHaveKey('w:nofollow');
    expect($f)->not->toHaveKey('w:href');
    expect($f)->toHaveKeys(['w:great', 'w:link']);
});

it('keeps an address or a link between angle brackets out of the tags', function (): void {
    $f = features('From: John <john@example.com>, see <https://evil.example/x> now');

    expect($f)->toHaveKeys(['mail:example.com', 'host:evil.example', 'tld:example', 'path:x']);
    expect(keysWithPrefix($f, 'tag:'))->toBe([]);
});

it('ignores a made-up tag name', function (): void {
    $f = features('<foo bar="1">text</foo> <br>');

    expect(keysWithPrefix($f, 'tag:'))->toBe(['tag:br']);
    expect($f)->toHaveKeys(['w:foo', 'w:text']);
});

it('does not take a comparison for a tag', function (): void {
    $f = features('if 3 < n and n > 2 then');

    expect(keysWithPrefix($f, 'tag:'))->toBe([]);
    expect($f)->toHaveKeys(['w:and', 'w:then']);
});

it('keeps a link that carries a user name', function (): void {
    $f = features('http://user@host.example/a');

    expect($f)->toHaveKeys(['url:', 'host:host.example', 'path:a']);
    expect($f)->not->toHaveKey('mail:host.example');
});

it('decodes HTML entities before tokenising', function (): void {
    $f = features('caf&eacute; &amp; th&#233;');

    expect($f)->toHaveKeys(['w:café', 'w:thé']);
});

it('counts exclamation marks and currency symbols', function (): void {
    $f = features('WIN NOW!!! Only 5€ or $10');

    expect($f['punct:!'])->toBe(3);
    expect($f['sym:€'])->toBe(1);
    expect($f['sym:$'])->toBe(1);
});

it('strips zero-width characters used to break words', function (): void {
    $f = features("via\u{200B}gra");

    expect($f)->toHaveKey('w:viagra');
});

it('drops single letters as words but keeps them for bigram breaks', function (): void {
    $f = features("l'agence a répondu");

    expect($f)->not->toHaveKey('w:l');
    expect($f)->not->toHaveKey('w:a');
    expect($f)->toHaveKeys(['w:agence', 'w:répondu']);
    expect($f)->not->toHaveKey('w2:agence_répondu');
});

it('returns an empty bag for an empty or blank text', function (): void {
    expect(features(''))->toBe([]);
    expect(features("  \n\t "))->toBe([]);
});

it('keeps the text and adds a marker when a regular expression gives up', function (): void {
    $guarded = new ReflectionMethod(FeatureExtractor::class, 'guarded');
    $features = [];
    $add = static function (string $feature) use (&$features): void {
        $features[$feature] = ($features[$feature] ?? 0) + 1;
    };

    expect($guarded->invoke(null, 'cleaned', 'original', $add))->toBe('cleaned');
    expect($features)->toBe([]);

    expect($guarded->invoke(null, null, 'original', $add))->toBe('original');
    expect($features)->toBe(['pcre:' => 1]);
});

it('keeps the words of hostile texts, flagged or not', function (): void {
    $e = new FeatureExtractor();
    $hostile = [
        str_repeat('a.', 25000),
        str_repeat('a-.', 17000),
        'www.' . str_repeat('a-', 25000),
        str_repeat('a@', 25000),
        'x@' . str_repeat('a.', 25000),
        str_repeat('<a ', 17000),
        str_repeat('&amp;', 10000),
        str_repeat('!', 100000),
    ];

    foreach ($hostile as $text) {
        // Very long dotted runs make the link pattern hit the PCRE JIT stack
        // limit: the text is then flagged, and its words still count
        $features = $e->extract($text . ' free SEO audit');
        expect($features)->toHaveKey('w:free');
        expect($features)->toHaveKey('w2:free_seo');
    }
});
