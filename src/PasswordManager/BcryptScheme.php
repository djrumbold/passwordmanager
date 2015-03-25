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

class BcryptScheme implements PasswordSchemeInterface
{
    /**
     * {@inheritdoc}
     */
    public function getId()
    {
        return 'Bcrypt';
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

            $info = password_get_info($user_password->getPassword());
            if (!$info || !is_array($info) || !array_key_exists('algo', $info))
                break;

            if ($info['algo'] !== PASSWORD_BCRYPT)
                break;

            $valid = password_verify($password_to_check, $user_password->getPassword());
            break;
        }

        return $valid;
    }

    /**
     * {@inheritdoc}
     */
    public function createPassword(UserPasswordInterface $user_password, $raw_password)
    {
        // Intentionally ignore the salt parameter because password_hash will
        // generate one automatically.
        $hashed_password = password_hash($raw_password, PASSWORD_BCRYPT);

        $user_password->setPasswordScheme($this->getId());
        $user_password->setPassword($hashed_password);
        $user_password->setSalt(null);
    }
}