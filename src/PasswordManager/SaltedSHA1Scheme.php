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

class SaltedSHA1Scheme implements PasswordSchemeInterface
{
    public function getId()
    {
        return 'SaltedSHA1';
    }

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

            $valid = sha1($user_password->getSalt().$password_to_check) === $user_password->getPassword();
            break;
        }

        return $valid;
    }

    public function createPassword($raw_password, $salt = null)
    {
        $hashed_password = sha1($salt.$raw_password);

        return $hashed_password;
    }
}