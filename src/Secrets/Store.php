<?php

namespace Re2bit\Secrets;

use ErrorException;
use InvalidArgumentException;
use RuntimeException;

class Store
{
    const PHP_FILE_EXTENSION = '.php';
    const ENCRYPT_PUBLIC_FILENAME = 'encrypt.public';
    const DECRYPT_PRIVATE_FILENAME = 'decrypt.private';
    const LIST_FILENAME = 'list';
    const ENCODED_DATA_FORMAT = "<?php // %s on %s\n\nreturn \"%s\";\n";
    const DATE_FORMAT = 'r';
    const LIST_DATA_FORMAT = "<?php\n\nreturn %s;\n";

    /**
     * @var string
     */
    private $secretsDir;

    /**
     * @var string
     */
    private $encryptPublicFilename;

    /**
     * @var string
     */
    private $decryptPrivateFilename;
    /**
     * @var string
     */
    private $pathPrefix;
    /**
     * @var string
     */
    private $listFilename;

    /**
     * @param string $secretDir
     * @param string $encryptPublicFilename
     * @param string $decryptPrivateFilename
     * @param string $listFilename
     */
    public function __construct(
        $secretDir,
        $encryptPublicFilename = self::ENCRYPT_PUBLIC_FILENAME,
        $decryptPrivateFilename = self::DECRYPT_PRIVATE_FILENAME,
        $listFilename = self::LIST_FILENAME
    ) {
        $this->secretsDir = $secretDir;
        $this->pathPrefix = $this->createPathPrefix();
        $this->encryptPublicFilename = $encryptPublicFilename;
        $this->decryptPrivateFilename = $decryptPrivateFilename;
        $this->listFilename = $listFilename;
    }

    /**
     * @return bool
     */
    public function hasEncryptKey()
    {
        return file_exists($this->getFilenameWithPathAndExtension($this->encryptPublicFilename));
    }

    /**
     * @return bool
     */
    public function hasDecryptKey()
    {
        return file_exists($this->getFilenameWithPathAndExtension($this->decryptPrivateFilename));
    }

    /**
     * @return string|null
     */
    public function loadDecryptKey()
    {
        return $this->loadFromFile($this->getFilenameWithPathAndExtension($this->decryptPrivateFilename));
    }

    /**
     * @return string|null
     */
    public function loadEncryptKey()
    {
        return $this->loadFromFile($this->getFilenameWithPathAndExtension($this->encryptPublicFilename));
    }

    /**
     * @param string $filename
     * @return string|null
     */
    private function loadFromFile($filename)
    {
        if (!is_file($filename)) {
            return null;
        }
        return (string) include $filename;
    }

    /**
     * @param string $key
     * @throws ErrorException
     * @return void
     */
    public function saveEncryptionKey($key)
    {
        $this->validateParameter($key, 'key');
        $this->saveToFile($this->getFilenameWithPathAndExtension($this->encryptPublicFilename), $key);
    }

    /**
     * @param string $key
     * @throws ErrorException
     * @return void
     */
    public function saveDecryptionKey($key)
    {
        $this->validateParameter($key, 'key');
        $this->saveToFile($this->getFilenameWithPathAndExtension($this->decryptPrivateFilename), $key);
    }

    /**
     * Saves a value to a file.
     *
     * @param string $name The name of the value.
     * @param string $value The value to save.
     * @throws ErrorException If there is an error while saving the value.
     * @return void
     */
    public function saveValue($name, $value)
    {
        $this->validateParameter($name, 'name');
        $this->validateParameter($value, 'value');

        $this->saveToFile(
            $this->getFileNameWithHashPathAndExtension($name),
            $value
        );
    }


    /**
     * @param string $name
     * @return bool
     */
    public function removeValue($name)
    {
        $this->validateParameter($name, 'name');

        $filename = $this->getFileNameWithHashPathAndExtension($name);
        return @unlink($filename) || !file_exists($filename);
    }


    /**
     * @param string $name
     * @return bool
     */
    public function valueExists($name)
    {
        $this->validateParameter($name, 'name');
        return file_exists($this->getFileNameWithHashPathAndExtension($name));
    }

    /**
     * @param string $name
     * @return string|null
     */
    public function loadValue($name)
    {
        $this->validateParameter($name, 'name');
        return rawurldecode((string) include $this->getFileNameWithHashPathAndExtension($name));
    }

    /**
     * Saves the encryption key to a file.
     *
     * @param string $filename The name of the file to save the key in
     * @param string $data The encryption key data
     *
     * @throws ErrorException If there is an error writing the key to the file
     * @return void
     */
    private function saveToFile($filename, $data)
    {
        $this->validateParameter($filename, 'filename');
        $this->validateParameter($data, 'data');

        $name = basename($filename);
        $data = str_replace('%', '\x', rawurlencode($data));
        $data = sprintf(self::ENCODED_DATA_FORMAT, $name, date(self::DATE_FORMAT), $data);
        $this->ensureSecretsDir();

        if (false === file_put_contents($filename, $data, LOCK_EX)) {
            $this->handleError();
        }
    }


    /**
     * @param array<string,string|null> $list
     * @throws ErrorException
     * @return void
     */
    public function updateListing($list)
    {
        $this->validateArrayParameter($list, 'list');

        $filename = $this->getFilenameWithPathAndExtension($this->listFilename);
        $data = sprintf(self::LIST_DATA_FORMAT, var_export($list, true));

        if (false === file_put_contents($filename, $data, LOCK_EX)) {
            $this->handleError();
        }
    }

    /**
     * Ensures that the secrets directory exists. If the directory does not exist, it will attempt to create it.
     *
     * @throws RuntimeException if unable to create the secrets directory
     * @return void
     */
    private function ensureSecretsDir()
    {
        if (
            $this->secretsDir
            && !is_dir($this->secretsDir)
            && !@mkdir($this->secretsDir, 0777, true)
            && !is_dir($this->secretsDir)
        ) {
            throw new RuntimeException(
                sprintf('Unable to create the secrets directory (%s).', $this->secretsDir)
            );
        }
    }

    /**
     * Returns the full filename by concatenating the given filename with the path prefix and file extension.
     *
     * @param string $filename The filename to concatenate with the path prefix and file extension.
     * @return string The full filename.
     */
    private function getFilenameWithPathAndExtension($filename): string
    {
        return $this->pathPrefix . $filename . self::PHP_FILE_EXTENSION;
    }

    /**
     * Returns the formatted filename by adding the hash if needed.
     *
     * @param string $filename The filename to format.
     * @return string The formatted filename.
     */
    private function getFileNameWithHashPathAndExtension($filename): string
    {
        return $this->getFilenameWithPathAndExtension(
            $filename . '.' . substr(md5($filename), 0, 6)
        );
    }

    /**
     * Handles the error and throws a new ErrorException.
     *
     * This method retrieves the last occurred error using error_get_last()
     * and throws a new ErrorException with the error message and type. If
     * the message or type is not available, it uses default values.
     *
     * @throws ErrorException When an error occurred.
     * @return null
     */
    protected function handleError()
    {
        $e = error_get_last();
        throw new ErrorException(
            isset($e['message']) ? $e['message'] : 'Failed to write secrets data.',
            0,
            isset($e['type']) ? $e['type'] : E_USER_WARNING
        );
    }

    /**
     * Create a path prefix for secret files.
     * The method replaces forward slashes in the secrets directory with DIRECTORY_SEPARATOR
     * and trims trailing DIRECTORY_SEPARATOR, then appends the base name of the secrets directory
     * and a dot at the end.
     *
     * @return string The generated path prefix for secret files.
     */
    protected function createPathPrefix()
    {
        return rtrim(
            str_replace(
                '/',
                DIRECTORY_SEPARATOR,
                $this->secretsDir
            ),
            DIRECTORY_SEPARATOR
        ) . DIRECTORY_SEPARATOR . basename($this->secretsDir) . '.';
    }

    /**
     * @param string $name
     * @param mixed $value
     * @throws InvalidArgumentException
     * @return void
     */
    protected function validateParameter($value, $name)
    {
        if (!is_string($value)) {
            throw new InvalidArgumentException("Parameter $name has to be String");
        }

        if (empty($value)) {
            throw new InvalidArgumentException("Parameter $name cannot be empty");
        }
    }

    /**
     * @param mixed $list
     * @param string $name
     * @return void
     */
    protected function validateArrayParameter($list, $name)
    {
        if (!is_array($list)) {
            throw new InvalidArgumentException("Parameter '$name' has to be an array");
        }
    }
}
