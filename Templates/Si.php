<?php

namespace Novutec\WhoisParser\Templates;

use Novutec\WhoisParser\Templates\Type\KeyValue;

class Si extends KeyValue
{
    protected $regexKeys = array(
        'name' => '/^domain$/i',
        'created' => '/^created$/i',
        'expires' => '/^expire$/i',
        'nameserver' => '/^nameserver$/i',
        'status' => '/^status$/i',

        // Registrar
        'registrar:name' => '/^registrar$/i',
        'registrar:url' => '/^registrar-url$/i',

        // Contacts: Owner
        'contacts:owner:handle' => '/^registrant$/i',

        // Haven't found a domain where Domain Holder and Tech aren't 'NOT DISCLOSED'
    );

    protected $available = '/^\% No entries found /im';
}
