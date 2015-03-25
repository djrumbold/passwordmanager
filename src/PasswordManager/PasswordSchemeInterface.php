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
}