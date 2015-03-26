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
 * Implementation of a crude salted SHA1 password hashing scheme.
 */
class SaltedSHA1Scheme implements PasswordSchemeInterface
{
    /**
     * {@inheritdoc}
     */
    public function getId()
    {
        return 'SaltedSHA1';
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

            if (!is_string($password_to_check))
                break;

            if ($user_password->getPassword() === null)
                break;

            if ($user_password->getSalt() === null)
                break;

            $valid = sha1($user_password->getSalt().$password_to_check) ===
                $user_password->getPassword();
            break;
        }

        return $valid;
    }

    /**
     * {@inheritdoc}
     */
    public function createPassword(UserPasswordInterface $user_password, $raw_password)
    {
        // Generate a random salt.

        $size = mcrypt_get_iv_size(MCRYPT_CAST_256, MCRYPT_MODE_CFB);
        $iv = mcrypt_create_iv($size, MCRYPT_DEV_URANDOM);
        $salt = sha1($iv);

        $hashed_password = sha1($salt.$raw_password);

        $user_password->setPasswordScheme($this->getId());
        $user_password->setPassword($hashed_password);
        $user_password->setSalt($salt);
    }
}