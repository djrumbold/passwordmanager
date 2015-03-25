<?php

use PasswordManager\PasswordManager;
use PasswordManager\UnsaltedSHA1Scheme;
use PasswordManager\SaltedSHA1Scheme;
use PasswordManager\BcryptScheme;
use PasswordManager\UserPassword;

class MigrationTest extends PHPUnit_Framework_TestCase
{
    public function testMigration()
    {
        $dodgy_scheme = new UnsaltedSHA1Scheme();
        $old_scheme = new SaltedSHA1Scheme();
        $new_scheme = new BcryptScheme();

        $pm = new PasswordManager($old_scheme);
        $pm->registerScheme($new_scheme);
        $pm->registerScheme($dodgy_scheme);

        // Firstly generate a user password using the Salted SHA 1 scheme

        $up = new UserPassword();
        $pm->createPassword($up, 'hello');

        $this->assertEquals('SaltedSHA1', $up->getPasswordScheme());
        $this->assertNotEquals(null, $up->getSalt());
        $this->assertNotEquals(null, $up->getPassword());

        $old_salt = $up->getSalt();
        $old_password = $up->getPassword();

        $this->assertTrue($pm->verifyPassword($up, 'hello'));

        // Now set a new designed password scheme

        $pm->setDesiredScheme($new_scheme);

        // Recheck password

        $this->assertTrue($pm->verifyPassword($up, 'hello'));

        // Examine the user password data again

        $this->assertEquals('Bcrypt', $up->getPasswordScheme());
        $this->assertEquals(null, $up->getSalt());
        $this->assertNotEquals(null, $up->getPassword());

        $this->assertTrue($pm->verifyPassword($up, 'hello'));
    }
}
