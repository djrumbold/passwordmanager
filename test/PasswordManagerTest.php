<?php

use PasswordManager\PasswordManager;
use PasswordManager\UnsaltedSHA1Scheme;
use PasswordManager\SaltedSHA1Scheme;
use PasswordManager\BcryptScheme;
use PasswordManager\UserPassword;

class PasswordManagerTest extends PHPUnit_Framework_TestCase
{
    public function testCreation()
    {
        $pm = new PasswordManager();
        $this->assertEquals('PasswordManager\PasswordManager', get_class($pm));
    }

    public function testUnsaltedSHA1SchemeVerification()
    {
        $scheme = new UnsaltedSHA1Scheme();
        $pm = new PasswordManager($scheme);

        $up = new UserPassword('aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d', 'UnsaltedSHA1');

        $this->assertEquals('aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d', $up->getPassword());
        $this->assertEquals('UnsaltedSHA1', $up->getPasswordScheme());

        $this->assertTrue($pm->verifyPassword($up, 'hello'));

        $this->assertFalse($pm->verifyPassword($up, 'goodbye'));
        $this->assertFalse($pm->verifyPassword($up, ''));
        $this->assertFalse($pm->verifyPassword($up, null));
    }

    public function testUnsaltedSHA1Scheme()
    {
        $scheme = new UnsaltedSHA1Scheme();
        $pm = new PasswordManager($scheme);
        $pm->registerScheme(new SaltedSHA1Scheme());
        $pm->registerScheme(new BcryptScheme());

        $up = new UserPassword();
        $pm->createPassword($up, 'test');

        $this->assertEquals('a94a8fe5ccb19ba61c4c0873d391e987982fbbd3', $up->getPassword());
        $this->assertEquals('UnsaltedSHA1', $up->getPasswordScheme());

        $this->assertTrue($pm->verifyPassword($up, 'test'));

        $this->assertFalse($pm->verifyPassword($up, 'goodbye'));
        $this->assertFalse($pm->verifyPassword($up, ''));
        $this->assertFalse($pm->verifyPassword($up, null));
    }
}
