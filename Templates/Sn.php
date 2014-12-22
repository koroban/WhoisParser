<?php

namespace Novutec\WhoisParser\Templates;

use Novutec\WhoisParser\Templates\Type\KeyValue;

class Sn extends KeyValue
{

    protected $regexKeys = array(
        'created' => '/^Date de creation$/i',
        'expires' => '/^Date d\'expiration$/i',
        'changed' => '/^Derniere modification$/i',
        'nameserver' => '/^Serveur[0-9]+\s*$/i',
        'status' => '/^Etat$/i',
        'registrar:name' => '/^Registrar$/i',

        // Contacts: Owner
        'contacts:owner:handle' => '/^Cod Registrant$/i',
        'contacts:owner:name' => '/^Nom Registrant$/i',
        'contacts:owner:address' => '/^Adresse Registrant$/i',
        'contacts:owner:city' => '/^Ville Registrant$/i',
        'contacts:owner:country' => '/^Pays Registrant$/i',
        'contacts:owner:phone' => '/^Telephone Registrant$/i',
        'contacts:owner:fax' => '/^Fax Registrant$/i',
        'contacts:owner:email' => '/^Courriel Registrant\.?$/i',

        // Contacts: Admin
        'contacts:admin:handle' => '/^ID Contact Admin/i',
        'contacts:admin:name' => '/^Nom Contact Admin$/i',
        'contacts:admin:phone' => '/^Telephone Contact Admin/i',
        'contacts:admin:fax' => '/^Fax Contact Admin$/i',
        'contacts:admin:email' => '/^Courriel Contact Admin\.?$/i',

        // Contacts: Tech
        'contacts:tech:handle' => '/^ID Contact Tech[0-9]?/i',
        'contacts:tech:name' => '/^Nom Contact Tech[0-9]?/i',
        'contacts:tech:phone' => '/^Telephone Contact Tech[0-9]?/i',
        'contacts:tech:fax' => '/^Fax Contact Tech[0-9]?/i',
        'contacts:tech:email' => '/^Courriel Contact Tech[0-9]?\.?$/i',
    );

    protected $available = array(
        '/^(.+?)\s*NOT FOUND\s*$/i',
    );


    public function reformatData()
    {
        $contactKeys = array(
            'Registrant',
            'Contact Admin',
            'Contact Admin1',
            'Contact Admin2',
            'Contact Admin3',
            'Contact Tech',
            'Contact Tech1',
            'Contact Tech2',
            'Contact Tech3',
        );

        foreach ($contactKeys as $key => $string) {
            if (! (array_key_exists('Nom '. $string, $this->data) && array_key_exists('Prenoms '. $string, $this->data))) {
                continue;
            }

            $firstname = $this->data['Prenoms '. $string];
            $lastname = $this->data['Nom '. $string];
            $this->data['Nom '. $string] = trim($firstname) .' '. trim($lastname);
        }
    }
}
