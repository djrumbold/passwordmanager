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
 * Implementation of a crude unsalted SHA1 password hashing scheme.
 *
 * This scheme is not recommended asa reliable password hashing tactic.
 * It is provided as an example of how one might migrate from an
 * existing scheme such as this.
 */
class UnsaltedSHA1Scheme implements PasswordSchemeInterface
{
    /**
     * {@inheritdoc}
     */
    public function getId()
    {
        return 'UnsaltedSHA1';
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

            if ($user_password->getPassword() === null)
                break;

            if (!is_string($password_to_check))
                break;

            if ($password_to_check === null)
                break;

            $valid = sha1($password_to_check) === $user_password->getPassword();
            break;
        }

        return $valid;
    }

    /**
     * {@inheritdoc}
     */
    public function createPassword(UserPasswordInterface $user_password, $raw_password)
    {
        $hashed_password = sha1($raw_password);

        $user_password->setPasswordScheme($this->getId());
        $user_password->setPassword($hashed_password);
        $user_password->setSalt(null);
    }
}