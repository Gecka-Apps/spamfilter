# spamfilter

A statistical spam filter for short texts submitted by strangers: contact
forms, comments, guestbook entries. Pure PHP, no external service, no rule
base. `classify()` returns a log-odds evidence figure for a text; `learn()`
and `unlearn()` update the counters it is computed from.

## Why another one

Statistical filters in PHP go back to [b8](https://nasauber.de/opensource/b8/),
which proved the idea for weblog comments in 2006. This project starts from
the same idea and changes what limits it on a contact form:

- **A model of ordinary language.** Most contact forms receive a lot of spam
  and very few legitimate messages. Learning from that alone, "hello",
  "thanks" and every word of the first message written in another language
  end up looking like spam. Here each word is weighed against its frequency
  in plain text, one background table per language (over 250 available, the
  text being matched to its own), so a common word of the language weighs
  nothing and only what stands out counts. A few legitimate messages then
  give usable scores where a plain naive Bayes filter needs a balanced
  corpus.
- **Language-agnostic features.** Words, word pairs, links, mail domains,
  number and punctuation shapes, normalised with Unicode NFKC and hashed into
  a fixed-size space; character n-grams for scripts written without spaces.
  Chinese, Japanese and `v1agra` are handled without a dictionary.
- **Sound combination.** Every feature weighs its log-likelihood ratio,
  summed over the text and normalised by its length, so a long message is
  not spam for being long and `explain()` shows exactly what drove a verdict.
- **Fast and small.** The model is an array of integers loaded once;
  classification is tokenisation plus additions, well under a millisecond.
- **Exact unlearning.** Everything is counters, so a wrongly learned text can
  be removed exactly, up to one rotation after it was learned.
- **Recent corrections in charge.** Counters live in two generations; old
  ones halve at each rotation, while what was learned since the last one
  keeps its full weight.

## How it works

### Features

`FeatureExtractor` turns a text into a bag of string features with counts.
HTML entities are decoded and zero-width characters removed first. Links come
out before anything else (`url:`, `host:`, `tld:`, `path:`), then mail
addresses (`mail:` with the domain only), then HTML tags whose name is a known
element (`tag:a`), so their parts are not cut into words a second time.
Currency symbols and exclamation marks give one feature per occurrence
(`sym:€`, `punct:!`), a word in capitals a `caps:` feature. The rest is
NFKC-normalised, lower-cased and split on anything that is not a letter or a
digit: a word of 2 to 40 characters is a `w:` feature, two consecutive words
with no punctuation between them a `w2:` feature, a run of digits a
`num:<length>` feature. A word in a script written without spaces (Han, kana,
Thai, Khmer, Lao, Myanmar) also yields character n-grams of 2 to 4 over the
word padded with `_` (`c3:_bo`); Latin and Cyrillic words do not, the n-grams
dilute the evidence there. Lengths are counted in characters, not bytes. No
stop-word list, no stemmer, no dictionary. Every regular expression runs
under the PCRE limits of the PHP configuration; when one gives up on a
text, the text keeps its other features and gets a `pcre:` marker rather
than slipping through with fewer features.

### Hashing and tables

Each feature is hashed with xxh3 to a 32-bit integer (`FeatureHasher`). A
model layer (`ClassCounts`) is two `CountTable`s, one per class, each 2^bits
32-bit counters (20 bits by default, 4 MB per table, 24 bits at most), plus
the number of texts learned per class. A hash is folded into a table by
masking, so tables of different sizes work from one hash; two features
landing on one slot share its counter, a loss that is negligible at 20 bits
for a site's vocabulary. Hash function and extraction rules are
versioned together as `FeatureHasher::VERSION`, written in every model
file, background table and storage, and a mismatch is refused.

### Scoring

For a feature w, with f_spam(w) and f_ham(w) its relative frequencies in each
class (count over the class total) and P_bg(w) its probability in plain
language, the estimator computes

    r(w) = ln( (f_spam(w) / P_bg(w) + μ) / (f_ham(w) / P_bg(w) + μ) )

Each class frequency is divided by the background, giving a lift: how many
times more often than in ordinary text the feature appears in that class.
μ (`backgroundWeight`, 10 by default) floors both lifts. A feature absent from
both classes scores exactly 0, a feature at background rate in both scores 0
as well, and a feature seen only in spam scores ln(1 + lift / μ), so one
feature cannot carry a verdict alone. When a pre-trained layer is given, its
counts join the site's with weight `pretrainedWeight` (0.5 by default) before
frequencies are taken.

A text's `logOdds` is the sum of r(w) over every feature occurrence (a
feature counted n times weighs n, or 1 + ln n with `logCounts`).
`Score::evidence()` divides it by the square root of the number of
occurrences: the raw sum favours long texts, the mean discards how much
evidence there is, the square root sits between, and it is the figure to put
thresholds on. `probability()` is a logistic squash of it for callers that
want [0, 1], not a calibrated posterior. `explain()` returns every feature of
the text with its count, its r(w) and its weight, strongest first.

This has the shape of naive Bayes, independent features and summed
log-likelihood ratios, with two departures: class frequencies are compared
through a background rather than with each other, and there is no class
prior. Those two make the estimator usable with hundreds of spam and ten
legitimate texts.

### Background and language

A background table is a `CountTable` of feature frequencies in ordinary text
of one language, built by spamfilter-backgrounds from whole sentences of the
Leipzig Corpora Collection, so that bigrams exist, with OpenSubtitles word
frequencies added for coverage and everyday sentences (Tatoeba, OpenSubtitles)
for the register of correspondence. P_bg(w) is the feature's count plus a
pseudo-count over the table's total; the pseudo-count is α times the
table's mean count per slot, 0.2 by default, so a feature the background
has never seen is rare rather than impossible, whatever the size of the
table. `LanguageBackground` holds one
table per loaded language and, for each text, picks the table under which the
text is most likely (sum over features of count × ln P(w | table)); the pick
doubles as a language detector, exposed as `SpamFilter::language()`. One table
mixing languages would understate every word of a monolingual text by the
share of its language in the mix. Without any background, P_bg falls back to
the marginal of everything learned, classes merged: the filter then only
knows that a feature is familiar, and every feature seen only in spam scores
the same whatever its count. That is the weakness of the no-background mode
and why a background is required in practice.

### Learning and storage

`learn()` and `unlearn()` add or subtract a text's feature counts in the
class table and move the class's text count by one; the two are exact
inverses on counters clamped at zero. With a `Storage`, every change is also
applied to the database as deltas inside one transaction and a version
counter moves. `PdoStorage` locks the generation row first, then does one
upsert per slot, visiting slots in a fixed order so concurrent transactions
take their row locks the same way, and joins a transaction the caller has
already opened. `SnapshotCache` keeps the in-memory layer in APCu, keyed by
the storage's identity, and `FileSnapshotCache` in a file stamped with it;
both rebuild it when the version has moved, and the file one also when the
identity does not match, as after a reinstall. A storage keeps every
counter twice, recent and archived, and loads their sum; `rotate()` shifts
the archive right by one bit and moves the recent counters into it, in one
statement. Background tables are read once from their compressed files and
cached in APCu by path and modification time.

### Cost

Classification is one pass of regular expressions over the text, one hash
per feature and one table lookup per feature and per layer: well under a
millisecond for a contact-form message with several languages loaded. Memory
is the tables, 4 MB per 20-bit table, so a site layer (two tables) plus two
languages is 16 MB, shared between requests when APCu is available. No
network call, no external service, no process beyond PHP.

## Requirements

PHP 8.2 or later with `ext-intl` and `ext-mbstring`. `ext-apcu` is optional,
see the caches below.

## Usage

Background tables (what ordinary text looks like, one per language) are
published separately by
[spamfilter-backgrounds](https://github.com/Gecka-Apps/spamfilter-backgrounds)
and downloaded for the languages your site receives:

```sh
vendor/bin/spamfilter-background --list
vendor/bin/spamfilter-background --to=/var/lib/mysite/spamfilter/background fr en
vendor/bin/spamfilter-background --to=/var/lib/mysite/spamfilter/background --check
vendor/bin/spamfilter-background --to=/var/lib/mysite/spamfilter/background --update
```

`--check` compares the directory with the latest release and exits with 1
when a table was republished, `--update` downloads those again and nothing
else, from a weekly scheduled task. The same from PHP:
`BackgroundDownloader::outdated($directory)` and `update($directory)`.

```php
use Gecka\SpamFilter\Label;
use Gecka\SpamFilter\Model\Background;
use Gecka\SpamFilter\SpamFilter;
use Gecka\SpamFilter\Storage\FileSnapshotCache;
use Gecka\SpamFilter\Storage\PdoStorage;

// The site's own counters live in SQLite or MariaDB
$storage = new PdoStorage(new PDO('sqlite:/var/lib/mysite/spamfilter.sqlite'));
$storage->install();                       // creates the tables, no-op afterwards

$filter = new SpamFilter(
    site: (new FileSnapshotCache($storage, '/var/lib/mysite/spamfilter/site.snapshot'))->load(),
    background: Background::load('/var/lib/mysite/spamfilter/background', ['fr', 'en']),
    storage: $storage,
);

$score = $filter->classify($message);
$score->evidence();     // > 0 leans spam, < 0 leans legitimate, 0 means nothing known
$score->probability();  // the same squashed into [0, 1]

// Three zones rather than one cut: deliver, flag for review, hold
$verdict = match (true) {
    $score->evidence() < 0.0 => 'deliver',
    $score->evidence() < 1.0 => 'review',
    default => 'hold',
};

// Every correction teaches the filter; keep the generation learn() returns,
// to take the text back exactly later
$learnedIn = $filter->learn($message, Label::Spam);
$filter->unlearn($message, Label::Spam, $learnedIn);

// Why that verdict
foreach ($filter->explain($message) as $contribution) {
    echo "$contribution->feature: $contribution->logRatio\n";
}

// Every few months, so that old counts stop outweighing recent corrections
$filter->rotate();
```

A background is required in production. Without one, P_bg falls back to the
counts learned so far, and until legitimate messages have been learned in
every language the site receives, any text in a language seen only in spam
scores as spam.

Deploy in scoring mode first, delivering everything, and learn the messages
as they are classified by hand. A few legitimate messages give usable
scores, a few dozen stable ones; no public corpus replaces them. The zone
boundaries above are a starting point: set them from the false positives
observed on the site, with `explain()` to see which features drove a
verdict.

The counters depend on how texts are cut into features. `FeatureExtractor`
takes options (word length limits, character n-grams, bigrams); changing
them after learning means the stored counts no longer describe the features
the filter sees, so relearn into a fresh storage. A change of the extraction
inside the library itself bumps `FeatureHasher::VERSION`, which every model
file and storage records, and a mismatch is refused with a message saying
what to rebuild.

Counters only grow: a campaign learned a thousand times two years ago weighs
as much as it did, while the site's vocabulary drifts. A storage therefore
keeps two generations of every counter. `learn()` adds to the recent one.
`rotate()` halves the archive, rounding down, adds the recent counters to
it and empties them: a text keeps its full weight until the rotation after
the one that archived it, then halves with each rotation, and the smallest
counts vanish. Call it from a scheduled task every few months, or earlier
once the recent generation holds a few thousand texts of a class
(`Storage::tally()` tells); the version moves, so cached snapshots reload.

A text dated before the last rotation, when a site learns what it already
holds, can go straight to the archive with `learn($text, $label,
Generation::Archive)`, where it weighs what it would had it been learned in
time.

`learn()` returns the generation the text belongs to, read in the same
transaction as the write so that a rotation running at that moment cannot
make it wrong; one less for a text sent to the archive. `unlearn()` requires
that number, so keep it with the text: a guess would subtract from a
generation that does not hold the text and erode the counts of other texts.
Within one rotation the text comes off exactly, from the recent counters or
from the archive; older, it was halved since, and `unlearn()` changes
nothing and returns false: learning the right class is then all a
correction can do.

The text counts a rotation halves are what the estimator weighs classes by.
`tally()->learned()` keeps the texts learned in all, never halved, which is
the figure to require before trusting the filter.

`PdoStorage` speaks SQLite, MySQL/MariaDB and PostgreSQL. SQLite is tested
in the unit suite; MariaDB and PostgreSQL through `compose.yaml`:

```sh
docker compose run --rm tests
```

### Another database

Implement the six methods of `Gecka\SpamFilter\Storage\Storage`
(`load()`, `apply()`, `rotate()`, `tally()`, `version()`, `identity()`)
and check your class against the rules the filter relies on, from any test
framework:

```php
use Gecka\SpamFilter\Testing\StorageContract;

StorageContract::verify(fn (int $bits) => new MyStorage(/* fresh and installed for $bits */));
```

It throws a `StorageContractViolation` naming the first rule broken.

## Caches

Without a cache, every request loads the site layer from the storage and
reads and decompresses each background table, 4 MB of memory per table.
Two caches keep the site layer between requests, both rebuilt from the
storage when its version has moved:

- `FileSnapshotCache` writes it to a file in a directory of the site, mode
  0600 in a directory created with mode 0700, through a temporary name
  renamed into place, and refuses a file of another user or with wider
  permissions. A deployment where a cron user and php-fpm share a group
  passes `mode: 0660, strict: false`. Wherever PHP runs under the site's own
  user, nothing else reads or alters the file. Use this one unless the next
  paragraph does not apply to you.
- `SnapshotCache` keeps it in APCu. `Background::load($path, $languages,
  apcu: true)` does the same for the background tables, decompressed once
  and shared by every process of the pool.

APCu is one memory segment for the whole PHP process pool, and every script
the pool runs reads and writes every entry in it. On a pool that serves
several sites, another site can read this one's counters, and learn by
hashing words whether they appear in its messages, and can replace them
with a model of its own that classifies whatever it likes. Use
`SnapshotCache` and `apcu: true` only on a pool that serves this site
alone. When in doubt, the file cache and plain `Background::load()` cost a
few milliseconds per request and nothing else.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).

---
Built with 🥥 and ☕ by [Gecka](https://gecka.nc) — Kanaky-New Caledonia 🇳🇨
