<?php

namespace Tests\Re2bit\Secrets;

if (PHP_VERSION_ID >= 70100) {
    class PhpUnitCompatibilityLayer extends \PHPUnit\Framework\TestCase
    {
        protected function setUp(): void
        {
            if (method_exists($this, '_setUp')) {
                $this->_setUp();
            }
        }

        protected function tearDown(): void
        {
            if (method_exists($this, '_tearDown')) {
                $this->_tearDown();
            }
        }
    }
    return;
}

class PhpUnitCompatibilityLayer extends \PHPUnit\Framework\TestCase
{
    /**
     * @return void
     */
    protected function setUp()
    {
        if (method_exists($this, '_setUp')) {
            $this->_setUp();
        }
    }

    /**
     * @return void
     */
    protected function tearDown()
    {
        if (method_exists($this, '_tearDown')) {
            $this->_tearDown();
        }
    }
}
