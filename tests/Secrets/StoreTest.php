<?php

namespace Tests\Re2bit\Secrets;

use ErrorException;
use InvalidArgumentException;
use Re2bit\Secrets\Store;
use Symfony\Component\Filesystem\Filesystem;

class StoreTest extends PhpUnitCompatibilityLayer
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
     * @return void
     */
    public function testHasEncryptKey()
    {
        $store = new Store($this->secretsDir);
        static::assertFalse($store->hasEncryptKey());
        $store->saveEncryptionKey('a');
        static::assertTrue($store->hasEncryptKey());
    }

    /**
     * @throws ErrorException
     * @return void
     */
    public function testHasDecryptKey()
    {
        $store = new Store($this->secretsDir);
        static::assertFalse($store->hasDecryptKey());
        $store->saveDecryptionKey('a');
        static::assertTrue($store->hasDecryptKey());
    }

    /**
     * @throws ErrorException
     * @return void
     */
    public function testStoreAndReceiveEncryptionKey()
    {
        $store = new Store($this->secretsDir);
        $originalKey = 'test123';
        $store->saveEncryptionKey($originalKey);
        $storeKey = $store->loadEncryptKey();
        static::assertSame($originalKey, $storeKey);
    }

    /**
     * @throws ErrorException
     * @return void
     */
    public function testStoreAndReceiveDecryptionKey()
    {
        $store = new Store($this->secretsDir);
        $originalKey = 'test123';
        $store->saveDecryptionKey($originalKey);
        $storeKey = $store->loadDecryptKey();
        static::assertSame($originalKey, $storeKey);
    }

    /**
     * @throws ErrorException
     * @return void
     */
    public function testSaveValue()
    {
        $store = new Store($this->secretsDir);
        $value = 'testValue';
        $store->saveValue('testKey', $value);
        static::assertTrue($store->valueExists('testKey'));
        static::assertSame($value, $store->loadValue('testKey'));
    }

    /**
     * @throws ErrorException
     * @return void
     */
    public function testRemoveValue()
    {
        $store = new Store($this->secretsDir);
        $value = 'testValue';
        $store->saveValue('testKey', $value);
        $store->removeValue('testKey');
        static::assertFalse($store->valueExists('testKey'));
    }

    /**
     * @throws ErrorException
     * @return void
     */
    public function testValueExists()
    {
        $store = new Store($this->secretsDir);
        static::assertFalse($store->valueExists('testKey'));
        $store->saveValue('testKey', 'testValue');
        static::assertTrue($store->valueExists('testKey'));
    }

    /**
     * @throws ErrorException
     * @return void
     */
    public function testLoadValue()
    {
        $store = new Store($this->secretsDir);
        $value = 'testValue';
        $store->saveValue('testKey', $value);
        static::assertSame($value, $store->loadValue('testKey'));
    }

    /**
     * @throws ErrorException
     * @return void
     */
    public function testEncryptionKeyCannotBeEmpty()
    {
        $this->expectException(InvalidArgumentException::class);
        $store = new Store($this->secretsDir);
        $store->saveEncryptionKey('');
    }

    /**
     * @throws ErrorException
     * @return void
     */
    public function testDecryptionKeyCannotBeEmpty()
    {
        $this->expectException(InvalidArgumentException::class);
        $store = new Store($this->secretsDir);
        $store->saveDecryptionKey('');
    }

    /**
     * @throws ErrorException
     * @return void
     */
    public function testSavedValueCannotBeFalse()
    {
        $this->expectException(InvalidArgumentException::class);
        $store = new Store($this->secretsDir);
        /** @phpstan-ignore-next-line */
        $store->saveValue('testKey', false);
    }
}
