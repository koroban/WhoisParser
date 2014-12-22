<?php

namespace Novutec\WhoisParser\Templates;

use Novutec\WhoisParser\Templates\Type\KeyValue;

class Se extends KeyValue
{
    protected $regexKeys = array(
        'name' => '/^domain$/i',
        'created' => '/^created$/i',
        'expires' => '/^expires$/i',
        'changed' => '/^modified$/i',
        'nameserver' => '/^nserver$/i',
        'dnssec' => '/^dnssec/i',
        'status' => '/^status$/i',
        'registrar:name' => '/^registrar$/i',
        'contacts:owner:handle' => '/^holder$/i',
        'contacts:admin:handle' => '/^admin-c$/i',
        'contacts:tech:handle' => '/^tech-c$/i',
        'contacts:billing:handle' => '/^billing-c$/i',
    );

    protected $available = array(
        '/^"([^"]+)" not found.$/im',
    );


    public function reformatData() {
        $contactHandles = array('holder', 'admin-c', 'tech-c', 'billing-c');
        foreach ($contactHandles as $key) {
            if (!array_key_exists($key, $this->data)) {
                continue;
            }

            $value = $this->data[$key];
            // If there's more than 1 entry, it's not going to be 'empty'
            if (is_array($value)) {
                continue;
            }

            if (trim($value) == '-') {
                unset($this->data[$key]);
            }
        }
    }
}
