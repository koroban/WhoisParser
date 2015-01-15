<?php

namespace Novutec\WhoisParser\Templates;

/**
 * Chengdu have a weird whois protection system where they blank out even values like creation date,
 * expiration date, etc with 'whois protect'.
 *
 * This template ignores those values.
 */
class Chengdu extends Standard {

    public function reformatData()
    {
        foreach ($this->data as $key => $value) {
            if (is_array($value)) {
                continue;
            }

            if (strtolower(trim($value)) == 'whois protect') {
                unset($this->data[$key]);
            }
        }
    }
}
