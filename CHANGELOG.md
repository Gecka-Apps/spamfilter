# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Statistical spam filter for short user-submitted texts: `classify()`,
  `learn()`, `unlearn()` and `explain()`, with exact unlearning.
- Feature extraction: NFKC lower-cased words, word bigrams stopping at
  punctuation, character n-grams for scripts written without spaces,
  links split into host, suffix and path, e-mail domains, HTML tag names,
  digit runs, capitalised words, exclamation marks and currency symbols.
  Features are hashed with xxh3 into fixed-size count tables.
- Lift-based estimator comparing each feature's frequency in spam and in
  legitimate text against a background frequency, with an unknown feature
  scoring exactly zero.
- Per-language background tables (what ordinary text looks like), chosen for
  each text by likelihood, downloaded on demand with `bin/spamfilter-background`
  from the spamfilter-backgrounds releases and kept current with its `--check`
  and `--update` commands (`BackgroundDownloader::outdated()` and `update()`
  from PHP).
- `Score::evidence()`, the summed log-odds over the square root of the text
  length, as the figure to put thresholds on.
- `PdoStorage` for SQLite, MySQL/MariaDB and PostgreSQL, with atomic delta
  upserts, a version counter, and a schema number (`PdoStorage::SCHEMA`)
  recorded at install and refused on mismatch.
- `FileSnapshotCache` and `SnapshotCache` (APCu) to keep the site layer
  between requests; APCu caching of background tables on request through
  `Background::load(..., apcu: true)`.
- Two generations of counters in every storage, recent and archived:
  `rotate()` halves the archive and moves the recent counters into it, so
  recent corrections outweigh old campaigns without being halved in their
  first period. `learn()` returns the generation the text belongs to and can
  send a dated text to the archive; `unlearn()` takes that generation back,
  refuses what a rotation halved since and rejects a generation that does
  not exist yet; `Storage::tally()` gives the generation number, the texts
  of the recent generation and the texts learned in all.
- `Testing\StorageContract` to check any storage implementation from any
  test framework.
