<?php

namespace Novutec\WhoisParser\Templates;

use Novutec\WhoisParser\Templates\Type\KeyValue;

class Su extends KeyValue
{

    protected $regexKeys = array(
        'name' => '/^domain$/i',
        'created' => '/^created$/i',
        'expires' => '/^paid-till$/i',
        'nameserver' => '/^nserver$/i',
        'status' => '/^state$/i',
        // Registrar
        'registrar:id' => '/^registrar$/i',
        // Contacts: Owner
        'contacts:owner:name' => '/^person$/i',
        'contacts:owner:organization' => '/^org$/i',
        'contacts:owner:phone' => '/^phone$/i',
        'contacts:owner:fax' => '/^fax$/i',
        'contacts:owner:email' => '/^e-mail$/i',
    );

    protected $available = '/No entries found/i';


    public function reformatData()
    {
        if (array_key_exists('state', $this->data) && (! is_array($this->data['state']))) {
            $this->data['state'] = explode(', ', $this->data['state']);
        }

        $dateFields = ['created', 'free-date', 'paid-till'];
        foreach ($dateFields as $field) {
            if (array_key_exists($field, $this->data)) {
                $this->data[$field] = str_replace('.', '-', $this->data[$field]);
            }
        }
    }
}
