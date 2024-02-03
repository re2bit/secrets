<?php

namespace Re2bit\Secrets;

use const DIRECTORY_SEPARATOR;
use function is_string;
use RuntimeException;

class DotenvVault extends AbstractVault
{
    /**
     * @var string
     */
    private $dotenvFile;

    /**
     * @param string $dotenvFile
     */
    public function __construct($dotenvFile)
    {
        $this->dotenvFile = str_replace('/', DIRECTORY_SEPARATOR, $dotenvFile);
    }

    /**
     * @param bool $override
     * @return bool
     */
    public function generateKeys($override = false)
    {
        $this->lastMessage = 'The dotenv vault doesn\'t encrypt secrets thus doesn\'t need keys.';

        return false;
    }

    /**
     * @param string $name
     * @param string $value
     * @return void
     */
    public function seal($name, $value)
    {
        $this->lastMessage = null;
        $this->validateName($name);
        $v = str_replace("'", "'\\''", $value);

        $content = is_file($this->dotenvFile) ? file_get_contents($this->dotenvFile) : '';

        if ($content === false) {
            throw new RuntimeException('Could not read file :"' . $this->dotenvFile . '"');
        }

        $content = preg_replace(
            "/^$name=((\\\\'|'[^']++')++|.*)/m",
            "$name='$v'",
            $content,
            -1,
            $count
        );

        if (!$count) {
            $content .= "$name='$v'\n";
        }

        file_put_contents($this->dotenvFile, $content);

        $this->lastMessage = sprintf('Secret "%s" %s in "%s".', $name, $count ? 'added' : 'updated', $this->getPrettyPath($this->dotenvFile));
    }

    /**
     * @param string $name
     * @return string|null
     */
    public function reveal($name)
    {
        $this->lastMessage = null;
        $this->validateName($name);
        $v = is_string(isset($_SERVER[$name]) ? $_SERVER[$name] : null) && 0 !== strpos($name, 'HTTP_') ? $_SERVER[$name] : (isset($_ENV[$name]) ? $_ENV[$name] : null);

        if (null === $v) {
            $this->lastMessage = sprintf('Secret "%s" not found in "%s".', $name, $this->getPrettyPath($this->dotenvFile));

            return null;
        }

        return $v;
    }

    /**
     * @param string $name
     * @return bool
     */
    public function remove($name)
    {
        $this->lastMessage = null;
        $this->validateName($name);

        $content = is_file($this->dotenvFile) ? file_get_contents($this->dotenvFile) : '';

        if ($content === false) {
            throw new RuntimeException('Could not read file :"' . $this->dotenvFile . '"');
        }

        $content = preg_replace(
            "/^$name=((\\\\'|'[^']++')++|.*)\n?/m",
            '',
            $content,
            -1,
            $count
        );

        if ($count) {
            file_put_contents($this->dotenvFile, $content);
            $this->lastMessage = sprintf('Secret "%s" removed from file "%s".', $name, $this->getPrettyPath($this->dotenvFile));

            return true;
        }

        $this->lastMessage = sprintf('Secret "%s" not found in "%s".', $name, $this->getPrettyPath($this->dotenvFile));

        return false;
    }

    /**
     * @param bool $reveal
     * @return array<string,string>
     */
    public function listing($reveal = false)
    {
        $this->lastMessage = null;
        $secrets = [];

        foreach ($_ENV as $k => $v) {
            if (preg_match('/^\w+$/D', $k)) {
                $secrets[$k] = $reveal ? $v : null;
            }
        }

        foreach ($_SERVER as $k => $v) {
            if (is_string($v) && preg_match('/^\w+$/D', $k)) {
                $secrets[$k] = $reveal ? $v : null;
            }
        }

        return $secrets;
    }
}
