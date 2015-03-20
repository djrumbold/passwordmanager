<?php

use PasswordManager\PasswordManager;

class PasswordManagerTest extends PHPUnit_Framework_TestCase
{
    public function testCreation()
    {
        $pm = new PasswordManager();
        $this->assertEquals('PasswordManager\PasswordManager', get_class($pm));
    }
}
