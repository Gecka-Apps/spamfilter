<?php

declare(strict_types=1);

// SPDX-License-Identifier: AGPL-3.0-or-later

use Gecka\SpamFilter\Model\Background;
use Gecka\SpamFilter\Model\BackgroundDownloader;
use Gecka\SpamFilter\Model\CountTable;
use Gecka\SpamFilter\Tokenizer\FeatureHasher;

/**
 * A published release laid out in a temporary directory, served over file://.
 *
 * @return array{dir: string, manifest: string, entries: array<string, array<string, mixed>>}
 */
function publishedTables(int $hashVersion = FeatureHasher::VERSION): array
{
    $dir = sys_get_temp_dir() . '/spamfilter-release-' . bin2hex(random_bytes(4));
    mkdir($dir);

    $entries = [];
    foreach (['fr' => 'French', 'en' => 'English'] as $code => $name) {
        $table = new CountTable(256);
        $table->add(crc32($code), 10);
        Background::write($table, "$dir/$code.bin");
        $entries[$code] = [
            'name' => $name,
            'file' => "$code.bin",
            'url' => "file://$dir/$code.bin",
            'bytes' => filesize("$dir/$code.bin"),
            'sha256' => hash_file('sha256', "$dir/$code.bin"),
        ];
    }

    file_put_contents("$dir/manifest.json", json_encode(['hash_version' => $hashVersion, 'languages' => $entries]));

    return ['dir' => $dir, 'manifest' => "file://$dir/manifest.json", 'entries' => $entries];
}

function removeDirectory(string $dir): void
{
    array_map('unlink', glob("$dir/*") ?: []);
    rmdir($dir);
}

it('lists the languages a manifest offers', function (): void {
    $release = publishedTables();

    expect((new BackgroundDownloader($release['manifest']))->available())->toBe(['fr' => 'French', 'en' => 'English']);

    removeDirectory($release['dir']);
});

it('downloads the requested tables and verifies them', function (): void {
    $release = publishedTables();
    $target = sys_get_temp_dir() . '/spamfilter-bg-' . bin2hex(random_bytes(4));

    $written = (new BackgroundDownloader($release['manifest']))->download(['fr'], $target);

    expect($written)->toBe(["$target/fr.bin"]);
    expect(file_exists("$target/en.bin"))->toBeFalse();
    expect(Background::load($target)->tables())->toHaveKey('fr');

    removeDirectory($target);
    removeDirectory($release['dir']);
});

it('refuses an unknown language', function (): void {
    $release = publishedTables();

    expect(fn() => (new BackgroundDownloader($release['manifest']))->download(['xx'], sys_get_temp_dir()))
        ->toThrow(InvalidArgumentException::class);

    removeDirectory($release['dir']);
});

it('refuses a table that does not match its checksum', function (): void {
    $release = publishedTables();
    // Corrupt the published file after the manifest was written
    file_put_contents("{$release['dir']}/fr.bin", 'tampered');
    $target = sys_get_temp_dir() . '/spamfilter-bg-' . bin2hex(random_bytes(4));

    expect(fn() => (new BackgroundDownloader($release['manifest']))->download(['fr'], $target))
        ->toThrow(RuntimeException::class, 'checksum');
    expect(is_dir($target) && glob("$target/*.bin") !== [])->toBeFalse();

    if (is_dir($target)) {
        rmdir($target);
    }
    removeDirectory($release['dir']);
});

it('refuses a download larger than the manifest announces', function (): void {
    $release = publishedTables();
    $manifest = json_decode((string) file_get_contents("{$release['dir']}/manifest.json"), true);
    $manifest['languages']['fr']['bytes'] = 10;
    file_put_contents("{$release['dir']}/manifest.json", json_encode($manifest));

    expect(fn() => (new BackgroundDownloader($release['manifest']))->download(['fr'], sys_get_temp_dir()))
        ->toThrow(RuntimeException::class, 'larger than announced');

    removeDirectory($release['dir']);
});

it('refuses a language code that is not one', function (): void {
    $release = publishedTables();

    expect(fn() => (new BackgroundDownloader($release['manifest']))->download(['../etc/x'], sys_get_temp_dir()))
        ->toThrow(InvalidArgumentException::class, 'not a language code');

    removeDirectory($release['dir']);
});

it('refuses tables published for another feature hash version', function (): void {
    $release = publishedTables(FeatureHasher::VERSION + 1);

    expect(fn() => (new BackgroundDownloader($release['manifest']))->download(['fr'], sys_get_temp_dir()))
        ->toThrow(RuntimeException::class, 'hash version');

    removeDirectory($release['dir']);
});

it('exposes the release the manifest names', function (): void {
    $release = publishedTables();
    $manifest = json_decode((string) file_get_contents("{$release['dir']}/manifest.json"), true);
    $manifest['version'] = 'v1.2';
    $manifest['generated'] = '2026-10-05T18:21:58+11:00';
    file_put_contents("{$release['dir']}/manifest.json", json_encode($manifest));

    $downloader = new BackgroundDownloader($release['manifest']);
    expect($downloader->version())->toBe('v1.2');
    expect($downloader->generated())->toBe('2026-10-05T18:21:58+11:00');

    // A manifest without them says nothing
    expect((new BackgroundDownloader(publishedTables()['manifest']))->version())->toBeNull();

    removeDirectory($release['dir']);
});

it('reports the tables of a directory that the release has changed or dropped', function (): void {
    $release = publishedTables();
    $target = sys_get_temp_dir() . '/spamfilter-bg-' . bin2hex(random_bytes(4));
    $downloader = new BackgroundDownloader($release['manifest']);
    $downloader->download(['fr', 'en'], $target);

    expect($downloader->outdated($target))->toBe([]);

    // A new French table is published, English is withdrawn, and a table of
    // a language the release never had sits in the directory
    $table = new CountTable(256);
    $table->add(crc32('fr'), 20);
    Background::write($table, "{$release['dir']}/fr.bin");
    $manifest = json_decode((string) file_get_contents("{$release['dir']}/manifest.json"), true);
    $manifest['languages']['fr']['bytes'] = filesize("{$release['dir']}/fr.bin");
    $manifest['languages']['fr']['sha256'] = hash_file('sha256', "{$release['dir']}/fr.bin");
    unset($manifest['languages']['en']);
    file_put_contents("{$release['dir']}/manifest.json", json_encode($manifest));
    copy("$target/fr.bin", "$target/xx.bin");

    $fresh = new BackgroundDownloader($release['manifest']);
    expect($fresh->outdated($target))->toBe([
        'en' => BackgroundDownloader::UNPUBLISHED,
        'fr' => BackgroundDownloader::CHANGED,
        'xx' => BackgroundDownloader::UNPUBLISHED,
    ]);

    // Updating fetches the changed table only and leaves the others alone
    expect($fresh->update($target))->toBe(["$target/fr.bin"]);
    expect(hash_file('sha256', "$target/fr.bin"))->toBe($manifest['languages']['fr']['sha256']);
    expect(file_exists("$target/en.bin"))->toBeTrue();
    expect($fresh->outdated($target))->toBe(['en' => BackgroundDownloader::UNPUBLISHED, 'xx' => BackgroundDownloader::UNPUBLISHED]);
    expect($fresh->update($target))->toBe([]);

    removeDirectory($target);
    removeDirectory($release['dir']);
});

it('refuses to compare with tables published for another feature hash version', function (): void {
    $release = publishedTables(FeatureHasher::VERSION + 1);

    expect(fn() => (new BackgroundDownloader($release['manifest']))->outdated(sys_get_temp_dir()))
        ->toThrow(RuntimeException::class, 'hash version');

    removeDirectory($release['dir']);
});
