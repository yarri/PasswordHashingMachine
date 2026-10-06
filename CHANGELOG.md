# Change Log

All notable changes to PasswordHashingMachine will be documented in this file.

## [Unreleased]

## [1.1] - 2026-10-06

- `addAlgorithm()` accepts an optional 4th callback, `$needs_rehash_callback($hash)`, so a hash produced by
  the current algorithm itself can still be flagged for re-hashing (e.g. outdated round/cost count).
- The by-reference output parameter of `verify()`/`checkPassword()` was renamed from `$is_legacy_hash` to
  `$need_rehash`. It's now `true` when the hash matched a legacy algorithm **or** when `$needs_rehash_callback`
  reports the current algorithm's hash as outdated.

## [1.0] - 2021-09-03

First official release
