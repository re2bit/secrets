<?php

namespace Re2bit\Secrets;

abstract class AbstractVault implements VaultInterface
{
    /**
     * @var null|string
     */
    protected $lastMessage;

    /**
     * @return string|null
     */
    public function getLastMessage()
    {
        return $this->lastMessage;
    }

    /**
     * @param bool $override
     * @return bool
     */
    abstract public function generateKeys($override = false);

    /**
     * @param string $name
     * @param string $value
     * @return void
     */
    abstract public function seal($name, $value);

    /**
     * @param string $name
     * @return string|null
     */
    abstract public function reveal($name);

    /**
     * @param string $name
     * @return bool
     */
    abstract public function remove($name);

    /**
     * @param bool $reveal
     * @return array<string,string>
    */
    abstract public function listing($reveal = false);

    /**
     * @param string $name
     * @return void
     */
    protected function validateName($name)
    {
        if (!preg_match('/^\w++$/D', $name)) {
            throw new \LogicException(sprintf('Invalid secret name "%s": only "word" characters are allowed.', $name));
        }
    }

    /**
     * @param string $path
     * @return string
     */
    protected function getPrettyPath($path)
    {
        return str_replace(getcwd() . \DIRECTORY_SEPARATOR, '', $path);
    }
}
