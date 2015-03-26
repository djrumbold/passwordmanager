<?php

/*
 * This file is part of PasswordManager.
 *
 * (c) Duncan Rumbold
 *
 * For the full copyright and license information, please view the
 * LICENSE.md file the accompanies this code.
 */

namespace PasswordManager;

/**
 * Implementation of SHA256 password hashing scheme using PHP's
 * legacy crypt() function.
 *
 * Use of this class is not recommended for users of PHP version
 * 5.5 or newer - use a class which utilises the password_ functions
 * instead.
 */
class LegacyCryptSHA256Scheme implements PasswordSchemeInterface
{
    /**
     * {@inheritdoc}
     */
    public function getId()
    {
        return 'LegacyCryptSHA256';
    }

    /**
     * {@inheritdoc}
     */
    public function verifyPassword(UserPasswordInterface $user_password, $password_to_check)
    {
        $valid = false;
        for (;;) {
            if ($user_password === null)
                break;

            if ($password_to_check === null)
                break;

            if ($user_password->getPassword() === null)
                break;

            if ($user_password->getSalt() === null)
                break;

            $valid = ($user_password->getPassword() ===
                      crypt($password_to_check, $user_password->getSalt()));
            break;
        }

        return $valid;
    }

    /**
     * {@inheritdoc}
     */
    public function createPassword(UserPasswordInterface $user_password, $raw_password)
    {
        // Format salt according to crypt() documentation.

        $salt = mcrypt_create_iv(16, MCRYPT_DEV_URANDOM);

        // Courtesy of https://github.com/ircmaxell/password_compat

        $base64_digits = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
        $bcrypt64_digits = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        $encoded = base64_encode($salt);
        $salt = strtr(rtrim($encoded, '='), $base64_digits, $bcrypt64_digits);

        $salt = substr($salt, 0, 16);
        $sha256_prefix = '$5$';
        $salt = $sha256_prefix.$salt;

        $hashed_password = crypt($raw_password, $salt);

        $user_password->setPasswordScheme($this->getId());
        $user_password->setPassword($hashed_password);
        $user_password->setSalt($salt);
    }
}