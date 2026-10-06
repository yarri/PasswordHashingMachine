# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

PasswordHashingMachine is a small PHP library (`Yarri\PasswordHashingMachine`) for hashing and verifying
passwords against a chain of pluggable hashing algorithms. It lets an application register one "current"
algorithm plus any number of legacy algorithms, so old hashes (e.g. md5) keep verifying while new passwords
are hashed with the current algorithm. See README.md for full usage examples.

## Commands

Install dependencies:

    composer install

Run the test suite (uses the ATK14 `tester` runner, not PHPUnit, even though PHPUnit is present in vendor/):

    cd test && ../vendor/bin/run_unit_tests

Run a single test file:

    cd test && ../vendor/bin/run_unit_tests tc_password_hashing_machine

CI (`.travis.yml`) runs across PHP 5.6 through 8.4 via `composer update --dev && cd test && ../vendor/bin/run_unit_tests`.

## Architecture

- `src/password_hashing_machine.php` — the entire public API, class `Yarri\PasswordHashingMachine`:
  - `addAlgorithm($hash_callback, $is_hash_callback = null, $check_password_callback = null, $needs_rehash_callback = null)`
    appends an algorithm to an internal ordered list. The **first** algorithm registered is the default/current
    one used by `hash()`. Later ones are only consulted during `verify()`/`isHash()` for legacy-hash support.
    - If `$is_hash_callback` is omitted, it's inferred by hashing the string `"check"` and, if the result is
      hex, building a regex matching that exact hex length (works for md5/sha1/sha2-style hex digests).
    - If `$check_password_callback` is omitted, it's derived by simply re-hashing the password with
      `$hash_callback` and comparing strings — only valid for deterministic, unsalted hash functions.
    - If `$needs_rehash_callback($hash)` is omitted, it defaults to always `false`. Use it to flag hashes
      produced by *this same* algorithm as outdated (e.g. a blowfish hash with fewer rounds than currently
      configured) — see `test_needs_rehash_on_current_algorithm` for the pattern.
  - `hash($password)` — hashes with algorithm `[0]` only; throws `PasswordHashingMachine\HashingFailedException`
    if the callback returns an empty string, or `NoAlgorithmException` if none registered.
  - `isHash($password)` — true if any registered algorithm's `is_hash_callback` matches.
  - `filter($password)` — returns empty/null input unchanged, returns existing valid hashes unchanged
    (via `isHash()`), otherwise hashes with the current algorithm. Used to normalize a value that might be a
    plaintext password or might already be a hash.
  - `verify($password, $hash, &$need_rehash = null)` — walks algorithms in registration order, skips any
    whose `is_hash_callback` doesn't match `$hash`, and returns true on the first `check_password_callback`
    match. Sets `$need_rehash` (by reference) to true if the match came from an algorithm other than index 0
    (legacy), **or** if `needs_rehash_callback($hash)` for the matched algorithm (including index 0) returns
    true — this is how callers detect "needs re-hash with the current algorithm/parameters".
  - `checkPassword()` is a plain alias for `verify()`.
  - Exceptions live under `src/password_hashing_machine/` as `Yarri\PasswordHashingMachine\{NoAlgorithmException,HashingFailedException}`.
- Algorithms are supplied entirely by the calling application as closures (hash/is_hash/check_password) — this
  library has no built-in hashing logic of its own beyond the hex-digest inference described above.
- Tests live in `test/tc_password_hashing_machine.php` as a single `TcPasswordHashingMachine extends TcBase`
  class (ATK14 tester convention: file `tc_foo.php` ↔ class `TcFoo`). `test/initialize.php` is the bootstrap
  loaded by the test runner (defines `MY_BLOWFISH_ROUNDS` and requires `vendor/autoload.php`). Tests exercise
  a three-algorithm chain (MyBlowfish current, md5, salted md5) plus a separate bcrypt-based scenario, and the
  two exception cases.
- Dev dependency `yarri/my-blowfish` (`vendor/yarri/my-blowfish`) supplies the `MyBlowfish` class used only in
  tests as a realistic bcrypt-like "current" algorithm.
