<?php

namespace Tests\Re2bit\Secrets;

use ErrorException;
use Re2bit\Secrets\SodiumVault;
use ReflectionClass;
use SodiumException;
use Symfony\Component\Filesystem\Filesystem;

class SodiumVaultTest extends PhpUnitCompatibilityLayer
{
    /** @var string */
    private $secretsDir;

    /**
     * @return void
     */
    protected function _setUp()
    {
        $this->secretsDir = sys_get_temp_dir() . '/sf_secrets/test/';
        (new Filesystem())->remove($this->secretsDir);
    }

    /**
     * @return void
     */
    protected function _tearDown()
    {
        (new Filesystem())->remove($this->secretsDir);
    }

    /**
     * @throws ErrorException
     * @throws SodiumException
     * @return void
     */
    public function testGenerateKeys()
    {
        $vault = new SodiumVault($this->secretsDir);

        $this->assertTrue($vault->generateKeys());

        $encryptionKeyFile = $this->secretsDir . '/test.encrypt.public.php';
        $decryptionKeyFile = $this->secretsDir . '/test.decrypt.private.php';

        $this->assertFileExists($encryptionKeyFile);
        $this->assertFileExists($decryptionKeyFile);

        $encKey = file_get_contents($encryptionKeyFile);
        static::assertNotEmpty($encKey);
        $decKey = file_get_contents($decryptionKeyFile);
        static::assertNotEmpty($decKey);

        $this->assertFalse($vault->generateKeys());
        $this->assertStringEqualsFile($encryptionKeyFile, $encKey);
        $this->assertStringEqualsFile($decryptionKeyFile, $decKey);

        $this->assertTrue($vault->generateKeys(true));
        $this->assertStringNotEqualsFile($encryptionKeyFile, $encKey);
        $this->assertStringNotEqualsFile($decryptionKeyFile, $decKey);

        $requiredEncryptionKey = require (string) $encryptionKeyFile;
        $requiredDecryptionKey = require (string) $decryptionKeyFile;

        $reflectionClass = new ReflectionClass($vault);
        $encryptionKeyProperty = $reflectionClass->getProperty('encryptionKey');
        $decryptionKeyProperty = $reflectionClass->getProperty('decryptionKey');
        $encryptionKeyProperty->setAccessible(true);
        $decryptionKeyProperty->setAccessible(true);

        static::assertSame($requiredEncryptionKey, $encryptionKeyProperty->getValue($vault));
        static::assertSame($requiredDecryptionKey, $decryptionKeyProperty->getValue($vault));
    }

    /**
     * @throws ErrorException
     * @throws SodiumException
     * @return void
     */
    public function testEncryptAndDecrypt()
    {
        $vault = new SodiumVault($this->secretsDir);
        $vault->generateKeys();

        $plain = "plain\ntext";

        $vault->seal('foo', $plain);

        $decrypted = $vault->reveal('foo');
        $this->assertSame($plain, $decrypted);

        $this->assertSame(['foo' => null], $vault->listing());
        $this->assertSame(['foo' => $plain], $vault->listing(true));

        $this->assertTrue($vault->remove('foo'));
        $this->assertFalse($vault->remove('foo'));

        $this->assertSame([], $vault->listing());
    }
}
