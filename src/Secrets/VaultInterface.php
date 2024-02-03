<?php

namespace Re2bit\Secrets;

interface VaultInterface
{
    /**
     * @return string|null
     */
    public function getLastMessage();

    /**
     * @param bool $override
     * @return bool
     */
    public function generateKeys($override = false);

    /**
     * @param string $name
     * @param string $value
     * @return void
     */
    public function seal($name, $value);

    /**
     * @param string $name
     * @return string|null
     */
    public function reveal($name);

    /**
     * @param string $name
     * @return bool
     */
    public function remove($name);

    /**
     * @param bool $reveal
     * @return array<string,string>
     */
    public function listing($reveal = false);
}
