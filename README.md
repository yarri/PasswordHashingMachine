PasswordHashingMachine
======================

[![Tests](https://github.com/yarri/PasswordHashingMachine/actions/workflows/tests.yml/badge.svg)](https://github.com/yarri/PasswordHashingMachine/actions/workflows/tests.yml)

PasswordHashingMachine is tool for hashing and checking passwords using a required hashing algorithm, which must be registered from the outside.

More hashing algorithms can be registered to PasswordHashingMachine so legacy hashes can be also successfully handled.

Usage
-----

### 1. Create the hashing machine

    $hasher = new Yarri\PasswordHashingMachine();

### 2. Add one or more hashing algorithms

    //  $hasher->addAlgorithm(
    //    callback $hash_callback,
    //    callback $is_hash_callback,
    //    callback $check_password_callback,
    //    callback $needs_rehash_callback
    //  );

The first added algorithm is also the default hashing algorithm.

    // default hashing algorithm - bcrypt
    $hasher->addAlgorithm(
      function($password){ return password_hash($password,PASSWORD_BCRYPT); },
      function($hash){ return (bool)preg_match('/^\$2[aby]\$\d{2}\$[.\/0-9A-Za-z]{53}$/',$hash); },
      function($password,$hash){ return password_verify($password,$hash); },
      function($hash){ return password_needs_rehash($hash,PASSWORD_BCRYPT); }
    );

The optional 4th callback `$needs_rehash_callback` tells PasswordHashingMachine that a hash, although
produced by this very algorithm, is outdated (e.g. it uses a lower cost/round count than currently
configured) and should be rehashed. When omitted, it defaults to always returning `false`.

Add another legacy hashing algorithms you need in your application.

    // algorithm for md5 hashes with common salt
    $hasher->addAlgorithm(
      function($password){ return md5(SITE_KEY.$password); },
      function($password){ return preg_match('/^[0-9a-f]{32}$/',$password); },
      function($password,$hash){ return md5(SITE_KEY.$password) === $hash; }
    );

    // algorithm for md5 hashes
    $hasher->addAlgorithm(
      function($password){ return md5($password); },
      function($password){ return preg_match('/^[0-9a-f]{32}$/',$password); },
      function($password,$hash){ return md5($password) === $hash; }
    );

In fact, for algorithms that provides hexadecimal hashes like md5, sha1, sha2, only the first callback is required.

    $hasher->addAlgorithm(
      function($password){ return sha1($password); }
    );

### 3. Use the machine

    // hashing passwords
    $hasher->hash("secret"); // e.g. '$2a$06$rLxnps2CuGC/9BPCq3ms..7uaWETN6GPiVMXYYGWqdQoMZsDQ/kFG'
    $hasher->hash('$2a$06$rLxnps2CuGC/9BPCq3ms..7uaWETN6GPiVMXYYGWqdQoMZsDQ/kFG'); // rehash! e.g. '$2y$10$XPuxlYvtelPKTpYtBpeAxOEuidftLo/kGkmmZgtWCFehvWz2N43wy'
    $hasher->hash(""); // e.g. '$2y$10$FZQFYFamZjnrUr1XvIdGTevA.iLQNSYvHXrP3LETn67AEGreuYCwe'

    // hashing password but preserving valid hashes or empty parameters
    $hasher->filter("secret"); // e.g. '$2a$06$rLxnps2CuGC/9BPCq3ms..7uaWETN6GPiVMXYYGWqdQoMZsDQ/kFG'
    $hasher->filter('$2a$06$rLxnps2CuGC/9BPCq3ms..7uaWETN6GPiVMXYYGWqdQoMZsDQ/kFG'); // '$2a$06$rLxnps2CuGC/9BPCq3ms..7uaWETN6GPiVMXYYGWqdQoMZsDQ/kFG'
    $hasher->filter(""); // ""
    $hasher->filter(null); // null

    // checking hashes
    $hasher->isHash($hash); // true
    $hasher->isHash("something"); // false
    $hasher->isHash(""); // false

    // verifying passwords
    $hasher->verify($password,$hash); // true or false

After a successful verification, the need for re-hashing can be detected and the password re-hashing using
the current hashing algorithm can be easily realized. This is the case either when the hash comes from a
legacy algorithm, or when it comes from the current algorithm but is outdated (e.g. lower round count).

    $hash = $user->getPasswordHash();
    if($hasher->verify($password,$hash,$need_rehash)){
      // the user is verified
      if($need_rehash){
         // transparent password re-hashing using the current hashing algorithm
         $current_hash = $hasher->hash($password);
         $user->setPasswordHash($current_hash);
      }
    }

Installation
------------

The best way how to install PasswordHashingMachine is to use the Composer:

    composer require yarri/password-hashing-machine

License
-------

PasswordHashingMachine is free software distributed [under the terms of the MIT license](http://www.opensource.org/licenses/mit-license)


[//]: # ( vim: set ts=2 et: )
