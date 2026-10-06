<?php

declare(strict_types=1);

// SPDX-License-Identifier: AGPL-3.0-or-later

use Gecka\SpamFilter\Label;
use Gecka\SpamFilter\Model\Background;
use Gecka\SpamFilter\Model\ClassCounts;
use Gecka\SpamFilter\Model\CountTable;
use Gecka\SpamFilter\Model\LanguageBackground;
use Gecka\SpamFilter\SpamFilter;
use Gecka\SpamFilter\Tokenizer\FeatureExtractor;
use Gecka\SpamFilter\Tokenizer\FeatureHasher;

/**
 * Two tiny "languages" built from a few sentences each.
 *
 * @return array<string, CountTable>
 */
function toyLanguages(): array
{
    $extractor = new FeatureExtractor();
    $hasher = new FeatureHasher();
    $tables = [];
    $sentences = [
        'fr' => ['bonjour je souhaite des renseignements sur la formation', 'merci pour votre réponse rapide', 'je voudrais une réunion la semaine prochaine'],
        'en' => ['hello I would like some information about the training', 'thank you for your quick reply', 'I would like a meeting next week'],
    ];
    foreach ($sentences as $language => $texts) {
        $table = new CountTable(1 << 12);
        foreach ($texts as $text) {
            foreach ($hasher->hashAll($extractor->extract($text)) as $hash => $count) {
                $table->add($hash, $count);
            }
        }
        $tables[$language] = $table;
    }

    return $tables;
}

it('detects the language a text is most likely written in', function (): void {
    $background = new LanguageBackground(toyLanguages());
    $hasher = new FeatureHasher();
    $extractor = new FeatureExtractor();

    expect($background->detect($hasher->hashAll($extractor->extract('je souhaite une réunion'))))->toBe('fr');
    expect($background->detect($hasher->hashAll($extractor->extract('I would like a meeting'))))->toBe('en');
});

it('refuses an empty set of tables', function (): void {
    expect(fn() => new LanguageBackground([]))->toThrow(InvalidArgumentException::class);
});

it('loads every table of a directory keyed by file name', function (): void {
    $dir = sys_get_temp_dir() . '/spamfilter-bg-' . bin2hex(random_bytes(4));
    foreach (toyLanguages() as $language => $table) {
        Background::write($table, "$dir/$language.bin");
    }

    $background = Background::load($dir);
    expect(array_keys($background->tables()))->toBe(['en', 'fr']);

    $single = Background::load("$dir/fr.bin");
    expect(array_keys($single->tables()))->toBe(['fr']);

    array_map('unlink', glob("$dir/*.bin") ?: []);
    rmdir($dir);
});

it('refuses a directory without tables', function (): void {
    expect(fn() => Background::load(sys_get_temp_dir()))->toThrow(RuntimeException::class);
});

it('scores a text against the background of its own language', function (): void {
    $languages = toyLanguages();
    $site = new ClassCounts(12);
    $site->learn((new FeatureHasher())->hashAll((new FeatureExtractor())->extract('cheap backlinks for your site')), Label::Spam);

    $perLanguage = new SpamFilter($site, background: new LanguageBackground($languages));
    $frenchOnly = new SpamFilter($site, background: $languages['fr']);
    $englishOnly = new SpamFilter($site, background: $languages['en']);

    $text = 'merci pour votre réponse';
    expect($perLanguage->language($text))->toBe('fr');
    expect($perLanguage->classify($text)->logOdds)->toBe($frenchOnly->classify($text)->logOdds);
    expect($perLanguage->classify('thank you for your reply')->logOdds)->toBe($englishOnly->classify('thank you for your reply')->logOdds);
    expect($frenchOnly->language($text))->toBeNull();
});
