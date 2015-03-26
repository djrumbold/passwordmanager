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
 * The intention of this interface is to abstract the password generation
 * and validating routines for the different password schemes that might
 * possibly be used. The PasswordManager doesn't need to know the specifics
 * about SHA1, SHA256, and bcrypt password hashing, only that they are
 * different and handled by different objects that conform to the same interface.
 *
 * Implement this interface in a way provides compatibiilty with your existing
 * user authentication system.
 */
interface PasswordSchemeInterface
{
    /**
     * Get the unique ID of this particular password scheme.
     *
     * @return string The scheme ID
     */
    public function getId();

    /**
     * Verify the password that has just been presented by the user
     * against the password information that has already been
     * associated with them.
     *
     * @param UserPasswordInterface $user_password The previously associated information.
     * @param string $password_to_check The newly presented password
     *
     * @return bool
     */
    public function verifyPassword(UserPasswordInterface $user_password, $password_to_check);

    /**
     * Create new password information for the newly presented password. The $user_password
     * parameter will be updated with the new information.
     *
     * @param UserPasswordInterface $user_password Password information to update
     * @param string $raw_password The newly presented password
     */
    public function createPassword(UserPasswordInterface $user_password, $raw_password);
}