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
 * The PasswordManager is chiefly responsible for providing functionality for:
 * 1) Hashing a supplied password with an elected password scheme.
 * 2) Checking a supplied password using an elected password scheme.
 * 3) Supporting an arbitrary of password hashing schemes.
 * 4) Migrating to a desired password scheme upon successful password validation.
 */
class PasswordManager
{
    protected $password_schemes;

    /**
     * Object constructor.
     *
     * @param PasswordSchemeInterface|null $desired_scheme May be used to set the desired password scheme that passwords will migrate to upon successful validation.
     */
    public function __construct(PasswordSchemeInterface $desired_scheme = null)
    {
        $this->password_schemes = array();
        $this->desired_scheme = $desired_scheme;

        if ($desired_scheme !== null)
            $this->registerScheme($desired_scheme);
    }

    /*
     * Register a password scheme.
     *
     * @param PasswordSchemeInterface $scheme The scheme to register.
     */
    public function registerScheme(PasswordSchemeInterface $scheme)
    {
        if (!array_key_exists($scheme->getId(), $this->password_schemes))
            $this->password_schemes[$scheme->getId()] = $scheme;
    }

    /*
     * Specify the desired password scheme. It will be registered automatically
     * if it hasn't been registered previously.
     *
     * @param PasswordSchemeInterface $desire_scheme The desired scheme.
     */
    public function setDesiredScheme(PasswordSchemeInterface $desired_scheme)
    {
        $this->desired_scheme = $desired_scheme;
        $this->registerScheme($desired_scheme);
    }

    /*
     * Hash the supplied password using the desired password hashing scheme.
     *
     * @param UserPasswordInterface $user_password Object to hold hashed password information.
     * @param string $raw_password The supplied password to hash.
     *
     * @return bool
     */
    public function createPassword(UserPasswordInterface $user_password, $raw_password)
    {
        if ($this->desired_scheme === null)
            return false;

        $coded_password = $this->desired_scheme->createPassword($user_password, $raw_password);

        return true;
    }

    /*
     * Verify a supplied password. The default scheme will be the one that has been
     * previously recorded in the supplied UserPassword object. If this is unspecified
     * or refers to an unregistered scheme then the function will fail (return false).
     * The function will return true upon successful verification or false otherwise.
     *
     * @param UserPasswordInterface $user_password Object to hold hashed password information.
     * @param string $raw_password The supplied password to verify.
     *
     * @return bool
     */
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

            $this->createPassword($user_password, $raw_password);
        }

        return true;
    }
}