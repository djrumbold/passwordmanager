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
 * An example 'in-memory' implementation of a class that conforms to
 * the UserPasswordInterface requirement.
 * In a given system, this class might be replaced by one with
 * persistance, or by a more general User class that could be combined
 * with something else that provides persistance.
 */
class UserPassword implements UserPasswordInterface
{
    protected $password;
    protected $scheme;
    protected $salt;

    public function __construct($password = null, $scheme = null, $salt = null)
    {
        $this->password = $password;
        $this->scheme = $scheme;
        $this->salt = $salt;
    }

    /**
     * {@inheritdoc}
     */
    public function getPassword()
    {
        return $this->password;
    }

    /**
     * {@inheritdoc}
     */
    public function setPassword($new_password)
    {
        $this->password = $new_password;
    }

    /**
     * {@inheritdoc}
     */
    public function getPasswordScheme()
    {
        return $this->scheme;
    }

    /**
     * {@inheritdoc}
     */
    public function setPasswordScheme($scheme_id)
    {
        $this->scheme = $scheme_id;
    }

    /**
     * {@inheritdoc}
     */
    public function getSalt()
    {
        return $this->salt;
    }

    /**
     * {@inheritdoc}
     */
    public function setSalt($salt)
    {
        $this->salt = $salt;
    }
}
