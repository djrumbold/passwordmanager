# PasswordManager

The purpose of this PHP class to handle the responsibility of setting and checking a user's password.

## Features

* Set a user's password.
* Check a user's password is valid.
* Able to perform hashing with different algorithms.
* Able to migrate the hashing algorithm e.g. migrate from sha1 to bcrypt when the password is set or checked.

## Description

The PasswordManager class achieves its purpose by abstracting the functionality specific to each different password hashing algorithm into separate classes. By implementing the PasswordScheme interface, one can encapsulate whatever password wrangling code is necessary so that PasswordManager can cooperate with any existing system. Five examples are supplied: Two SHA1 hashing algorithms (salted and unsalted) implemented in a way that might be typical of many existing systems, two 'legacy' schemes that demonstrate use of PHP's crypt() function to provide SHA256 and bcrypt hashing, and one that uses the newer (since PHP 5.5) recommended method of password hashing and checking. One or more (any aribtrary number) of these schemes can be registered with the PasswordManager as required.

Setting the 'desired' password scheme will mean that password information will be migrated to that scheme upon each successful verification.

## Usage

See the supplied unit tests for examples on how to instantiate the PasswordManager, register password schemes, create and verify passwords, and migrate passwords.

### Using password_ functions on pre-5.5 versions of PHP.

If you're wanting to write 'forward compatible' password schemes referencing the PHP 5.5 password functions but you're only running PHP 5.4 (say) then you're in luck. Go and find the password compatibility project at: https://github.com/ircmaxell/password_compat/blob/master/lib/password.php

