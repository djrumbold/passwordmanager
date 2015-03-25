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
 * The Password Manager needs to deal with a number of aspects
 * that represent information about a particular user's password.
 *
 * This interface provides an abstraction so that the relevant
 * variables can be managed and stored in whatever way is necessary
 * for the system, but presented through an object that implements
 * the interface in an appropriate way.
 */
interface UserPasswordInterface
{
    /**
     * Return the encoded, salted, persisted password.
     *
     * @return string password
     */
    public function getPassword();

    /**
     * Set an encoded, salted password to be stored by the system.
     *
     * @param string $new_password The new password
     */
    public function setPassword($new_password);

    /**
     * Return the ID of the password scheme used for encoding and
     * decoding the user's password.
     *
     * @return string|null The ID of the password scheme
     */
    public function getPasswordScheme();


    /**
     * Set the ID of the password scheme used for encoding and
     * decoding the users's password.
     *
     * @param string $scheme_id The ID of the password scheme
     */
    public function setPasswordScheme($scheme_id);

    /**
     * Return the salt that was used in the password encoding process.
     *
     * @return string|null The password salt
     */
    public function getSalt();

    /**
     * Set a new password salt, as used in the password encoding process.
     *
     * @param string|null $salt The password salt
     */
    public function setSalt($salt);
}
