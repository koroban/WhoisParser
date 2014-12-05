<?php

namespace Novutec\WhoisParser\Templates;

use Novutec\WhoisParser\Templates\Type\KeyValue;

class Vu extends KeyValue
{

    protected $regexKeys = array(
        'created' => '/^Date Created$/i',
        'expires' => '/^Expiry Date$/i',
        'nameserver' => '/^DNS servers[0-9]*$/i',
        // Contacts: Owner
        'contacts:owner:name' => '/^Full Name$/i',
        'contacts:owner:address' => '/^Adress$/i',
        'contacts:owner:city' => '/^City$/i',
        'contacts:owner:country' => '/^Country$/i',
    );

    protected $available = '/is not valid!/i';


    public function reformatData()
    {
        $name = '';
        if (array_key_exists('First Name', $this->data)) {
            $name = $this->data['First Name'];
        }
        if (array_key_exists('Last Name', $this->data)) {
            $name .= ' ' . $this->data['Last Name'];
        }
        $this->data['Full Name'] = trim($name);
    }
}
