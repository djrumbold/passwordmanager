<?php

use PasswordManager\PasswordManager;
use PasswordManager\UnsaltedSHA1Scheme;
use PasswordManager\UserPassword;

class PasswordManagerTest extends PHPUnit_Framework_TestCase
{
    public function testCreation()
    {
        $pm = new PasswordManager();
        $this->assertEquals('PasswordManager\PasswordManager', get_class($pm));
    }

    public function testUnsaltedSHA1Scheme()
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
}
