<?php

namespace Re2bit\Secrets;

use function dirname;
use ErrorException;
use function function_exists;
use function is_object;
use function is_string;
use const LOCK_EX;
use LogicException;
use RuntimeException;
use SodiumException;

class SodiumVault extends AbstractVault
{
    const PHP_FILE_EXTENSION = '.php';
    /** @var string|null */
    private $encryptionKey;

    /** @var string */
    private $decryptionKey;

    /** @var Store */
    private $store;

    /**
     * @param string|Store $store
     * @param mixed $decryptionKey A string or a stringable object that defines the private key to use to decrypt the vault
     *                                               or null to store generated keys in the provided $secretsDir
     */
    public function __construct($store, $decryptionKey = null)
    {
        if (null !== $decryptionKey && !is_string($decryptionKey) && !(is_object($decryptionKey) && method_exists($decryptionKey, '__toString'))) {
            throw new RuntimeException(sprintf('Decryption key should be a string or an object that implements the __toString() method'));
        }

        $this->decryptionKey = (string)$decryptionKey;
        if (is_string($store)) {
            $this->store = new Store($store);
        } elseif ($store instanceof Store) {
            $this->store = $store;
        } else {
            throw new RuntimeException('store must be a string or an Store object');
        }
    }

    /**
     * @param bool $override
     * @throws ErrorException
     * @throws SodiumException
     * @return bool
     */
    public function generateKeys($override = false)
    {
        if (!function_exists('sodium_crypto_box_keypair') || !function_exists('sodium_crypto_box_publickey')) {
            $this->lastMessage = 'CannotGenerate Keys, "sodium" PHP extension missing. Try running "composer require paragonie/sodium_compat" if you cannot enable the extension."';

            return false;
        }

        $this->lastMessage = null;

        if ((null === $this->encryptionKey) && '' !== $this->decryptionKey = (string) $this->decryptionKey) {
            $this->lastMessage = 'Cannot generate keys when a decryption key has been provided while instantiating the vault.';

            return false;
        }

        try {
            $this->loadKeys();
        } catch (RuntimeException $e) {
            // ignore failures to load keys
        }

        if ('' !== $this->decryptionKey && !$this->store->hasEncryptKey()) {
            $this->store->saveEncryptionKey((string)$this->encryptionKey);
        }

        if (!$override && null !== $this->encryptionKey) {
            //@todo update message
            $this->lastMessage = sprintf(
                'Sodium keys already exist at "%s*.{public,private}" and won\'t be overridden.',
                $this->getPrettyPath($this->store->getStoreLocation())
            );

            return false;
        }

        $this->decryptionKey = sodium_crypto_box_keypair();
        $this->encryptionKey = sodium_crypto_box_publickey($this->decryptionKey);

        $this->store->saveEncryptionKey($this->encryptionKey);
        $this->store->saveDecryptionKey($this->decryptionKey);

        //@todo update message
        $this->lastMessage = sprintf('Sodium keys have been generated at "%s*.public/private' . self::PHP_FILE_EXTENSION . '".', $this->getPrettyPath($this->store->getStoreLocation()));

        return true;
    }

    /**
     * @param string $name
     * @param string $value
     * @throws ErrorException
     * @throws SodiumException
     * @return void
     */
    public function seal($name, $value)
    {
        if (!function_exists('sodium_crypto_box_publickey') || !function_exists('sodium_crypto_box_seal')) {
            $this->lastMessage = sprintf('Secret "%s" cannot be sealed as the "sodium" PHP extension missing. Try running "composer require paragonie/sodium_compat" if you cannot enable the extension."', $name);

            return;
        }

        $this->lastMessage = null;
        $this->validateName($name);
        $this->loadKeys();
        $this->store->saveValue(
            $name,
            sodium_crypto_box_seal(
                $value,
                $this->encryptionKey ?? sodium_crypto_box_publickey($this->decryptionKey)
            )
        );

        $list = $this->listing();
        $list[$name] = null;
        uksort($list, 'strnatcmp');
        file_put_contents($this->store->getFilenameWithPathAndExtension('list'), sprintf("<?php\n\nreturn %s;\n", var_export($list, true)), LOCK_EX);

        $this->lastMessage = sprintf('Secret "%s" encrypted in "%s"; you can commit it.', $name, $this->getPrettyPath(dirname($this->store->getStoreLocation())));
    }

    /**
     * @param string $name
     * @throws SodiumException
     * @return string|null
     */
    public function reveal($name)
    {
        $this->lastMessage = null;
        $this->validateName($name);

        if (!$this->store->valueExists($name)) {
            $this->lastMessage = sprintf('Secret "%s" not found in "%s".', $name, $this->getPrettyPath(dirname($this->store->getStoreLocation())));

            return null;
        }

        if (!function_exists('sodium_crypto_box_seal') || !function_exists('sodium_crypto_box_seal_open')) {
            $this->lastMessage = sprintf('Secret "%s" cannot be revealed as the "sodium" PHP extension missing. Try running "composer require paragonie/sodium_compat" if you cannot enable the extension."', $name);

            return null;
        }

        $this->loadKeys();

        if ('' === $this->decryptionKey) {
            $this->lastMessage = sprintf('Secret "%s" cannot be revealed as no decryption key was found in "%s".', $name, $this->getPrettyPath(dirname($this->store->getStoreLocation())));

            return null;
        }

        if (false === $value = sodium_crypto_box_seal_open((string)$this->store->loadValue($name), $this->decryptionKey)) {
            $this->lastMessage = sprintf('Secret "%s" cannot be revealed as the wrong decryption key was provided for "%s".', $name, $this->getPrettyPath(dirname($this->store->getStoreLocation())));

            return null;
        }

        return $value;
    }

    /**
     * @param string $name
     * @return bool
     */
    public function remove($name)
    {
        $this->lastMessage = null;
        $this->validateName($name);

        if (!$this->store->valueExists($name)) {
            $this->lastMessage = sprintf('Secret "%s" not found in "%s".', $name, $this->getPrettyPath(dirname($this->store->getStoreLocation())));

            return false;
        }

        $list = $this->listing();
        unset($list[$name]);
        $this->store->updateListing($list);

        $this->lastMessage = sprintf('Secret "%s" removed from "%s".', $name, $this->getPrettyPath(dirname($this->store->getStoreLocation())));

        return $this->store->removeValue($name);
    }

    /**
     * @param bool $reveal
     * @throws SodiumException
     * @return array<string, string|null>
     */
    public function listing($reveal = false)
    {
        $this->lastMessage = null;

        if (!is_file($file = $this->store->getFilenameWithPathAndExtension('list'))) {
            return [];
        }

        $secrets = include $file;

        if (!$reveal) {
            return $secrets;
        }

        foreach ($secrets as $name => $value) {
            $secrets[$name] = $this->reveal($name);
        }

        return $secrets;
    }

    /**
     * @todo is this still relevant ?
     * @throws SodiumException
     * @return array
     * @return array<string,string|null>
     */
    public function loadEnvVars()
    {
        return $this->listing(true);
    }

    /**
     * @throws SodiumException|LogicException|RuntimeException
     * @return void
     */
    private function loadKeys()
    {
        if (!function_exists('sodium_crypto_box_seal') || !function_exists('sodium_crypto_box_publickey')) {
            throw new LogicException('The "sodium" PHP extension is required to deal with secrets. Alternatively, try running "composer require paragonie/sodium_compat" if you cannot enable the extension.".');
        }

        if (null !== $this->encryptionKey || '' !== $this->decryptionKey = (string) $this->decryptionKey) {
            return;
        }

        if ($this->store->hasDecryptKey()) {
            $this->decryptionKey = (string)$this->store->loadDecryptKey();
        }

        if ($this->store->hasEncryptKey()) {
            $this->encryptionKey = $this->store->loadEncryptKey();
        } elseif ('' !== $this->decryptionKey) {
            $this->encryptionKey = sodium_crypto_box_publickey($this->decryptionKey);
        } else {
            //@todo update message
            throw new RuntimeException(sprintf('Encryption key not found in "%s".', dirname($this->store->getStoreLocation())));
        }
    }
}
