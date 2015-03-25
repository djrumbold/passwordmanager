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

class PasswordManager
{
    protected $password_schemes;

    public function __construct(PasswordSchemeInterface $desired_scheme = null)
    {
        $this->password_schemes = array();
        $this->desired_scheme = $desired_scheme;

        if ($desired_scheme !== null)
            $this->registerScheme($desired_scheme);
    }

    public function registerScheme(PasswordSchemeInterface $desired_scheme)
    {
        $this->password_schemes[$desired_scheme->getId()] = $desired_scheme;
    }

    public function verifyPassword(UserPasswordInterface $user_password, $raw_password)
    {
        $scheme_id = $user_password->getPasswordScheme();

        if (!$scheme_id)
            return false;

        if (!array_key_exists($scheme_id, $this->password_schemes))
            return false;

        $scheme = $this->password_schemes[$scheme_id];

        $valid = $scheme->verifyPassword($user_password, $raw_password);

        if (!$valid)
            return false;

        if (($this->desired_scheme !== null) &&
            ($scheme->getId() !== $this->desired_scheme->getId())) {
            // The password was valid, but the desired password scheme has
            // changed. Re-encode their password using the new scheme
            // and record which scheme has been used.

            // Generate a random salt (may or may not actually be used
            // by the encoder).
            $size = mcrypt_get_iv_size(MCRYPT_CAST_256, MCRYPT_MODE_CFB);
            $iv = mcrypt_create_iv($size, MCRYPT_DEV_RANDOM);
            $salt = sha1($iv);

            $coded_password = $this->desired_scheme->createPassword($raw_password, $salt);
            $user_password->setPassword($coded_password);
            $user_password->setPasswordScheme($this->desired_scheme->getId());
        }

        return true;
    }
}