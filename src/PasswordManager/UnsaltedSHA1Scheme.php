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