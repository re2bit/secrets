<?php

namespace Tests\Re2bit\Secrets;

use Re2bit\Secrets\DotenvVault;
use Symfony\Component\Dotenv\Dotenv;

class DotenvVaultTest extends PhpUnitCompatibilityLayer
{
    /** @var string */
    private $envFile;

    /**
     * @return void
     */
    protected function _setUp()
    {
        $this->envFile = sys_get_temp_dir() . '/sf_secrets.env.test';
        @unlink($this->envFile);
    }

    /**
     * @return void
     */
    protected function _tearDown()
    {
        @unlink($this->envFile);
    }

    /**
     * @return void
     */
    public function testGenerateKeys()
    {
        $vault = new DotenvVault($this->envFile);

        $this->assertFalse($vault->generateKeys());
        $this->assertSame('The dotenv vault doesn\'t encrypt secrets thus doesn\'t need keys.', $vault->getLastMessage());
    }

    /**
     * @return void
     */
    public function testEncryptAndDecrypt()
    {
        $vault = new DotenvVault($this->envFile);

        $plain = "plain\ntext";

        $vault->seal('foo', $plain);

        unset($_SERVER['foo'], $_ENV['foo']);
        (new Dotenv())->load($this->envFile);

        $decrypted = $vault->reveal('foo');
        $this->assertSame($plain, $decrypted);

        $this->assertSame(['foo' => null], array_intersect_key($vault->listing(), ['foo' => 123]));
        $this->assertSame(['foo' => $plain], array_intersect_key($vault->listing(true), ['foo' => 123]));

        $this->assertTrue($vault->remove('foo'));
        $this->assertFalse($vault->remove('foo'));

        unset($_SERVER['foo'], $_ENV['foo']);
        (new Dotenv())->load($this->envFile);

        $this->assertArrayNotHasKey('foo', $vault->listing());
    }
}
