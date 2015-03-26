<?php

use PasswordManager\PasswordManager;
use PasswordManager\UnsaltedSHA1Scheme;
use PasswordManager\SaltedSHA1Scheme;
use PasswordManager\BcryptScheme;
use PasswordManager\LegacyBcryptScheme;
use PasswordManager\LegacyCryptSHA256Scheme;
use PasswordManager\UserPassword;

class MigrationTest extends PHPUnit_Framework_TestCase
{
    public function testMigrationSaltedSHA1ToBcrypt()
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

    public function testMigrationSHA256ToLegacyBcrypt()
    {
        $old_scheme = new LegacyCryptSHA256Scheme();
        $new_scheme = new LegacyBcryptScheme();

        $pm = new PasswordManager($old_scheme);
        $pm->registerScheme($new_scheme);

        // Firstly generate a user password using the SHA 256 scheme

        $up = new UserPassword();
        $pm->createPassword($up, 'hello');

        $this->assertEquals('LegacyCryptSHA256', $up->getPasswordScheme());
        $this->assertNotEquals(null, $up->getSalt());
        $this->assertNotEquals(null, $up->getPassword());

        $this->assertTrue($pm->verifyPassword($up, 'hello'));

        // Now set a new designed password scheme

        $pm->setDesiredScheme($new_scheme);

        // Recheck password

        $this->assertTrue($pm->verifyPassword($up, 'hello'));

        // Examine the user password data again

        $this->assertEquals('LegacyBcrypt', $up->getPasswordScheme());
        $this->assertEquals(29, strlen($up->getSalt()));
        $this->assertEquals('$2y$10$', substr($up->getSalt(), 0, 7));
        $this->assertNotEquals(null, $up->getPassword());

        $this->assertTrue($pm->verifyPassword($up, 'hello'));
    }

    public function testMigrationUnsaltedSHA1ToBcrypt()
    {
        $old_scheme = new UnsaltedSHA1Scheme();
        $new_scheme = new BcryptScheme();

        $pm = new PasswordManager($old_scheme);
        $pm->registerScheme($new_scheme);

        // Firstly generate a user password using the Unsalted SHA 1 scheme

        $up = new UserPassword();
        $pm->createPassword($up, 'hello');

        $this->assertEquals('UnsaltedSHA1', $up->getPasswordScheme());
        $this->assertEquals(null, $up->getSalt());
        $this->assertNotEquals(null, $up->getPassword());

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

    public function testNoMigrationOnNoVerification()
    {
        $old_scheme = new LegacyCryptSHA256Scheme();
        $new_scheme = new LegacyBcryptScheme();

        $pm = new PasswordManager($old_scheme);
        $pm->registerScheme($new_scheme);

        // Firstly generate a user password using the SHA 256 scheme

        $up = new UserPassword();
        $pm->createPassword($up, 'hello');

        $this->assertEquals('LegacyCryptSHA256', $up->getPasswordScheme());
        $this->assertNotEquals(null, $up->getSalt());
        $this->assertNotEquals(null, $up->getPassword());

        $this->assertTrue($pm->verifyPassword($up, 'hello'));

        // Now set a new designed password scheme

        $pm->setDesiredScheme($new_scheme);

        // Recheck password but get it wrong

        $this->assertFalse($pm->verifyPassword($up, 'iforgot'));

        // Examine the user password data again - nothing should have changed

        $this->assertEquals('LegacyCryptSHA256', $up->getPasswordScheme());
        $this->assertNotEquals(null, $up->getSalt());
        $this->assertNotEquals(null, $up->getPassword());
    }
}
