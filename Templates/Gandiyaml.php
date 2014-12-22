<?php

namespace Novutec\WhoisParser\Templates;

use Novutec\WhoisParser\Templates\Type\Yaml;

class Gandiyaml extends Yaml
{
    protected $data = array();

    protected $regexKeys = array(
        'name' => '/^domain$/i',
        'created' => '/^reg_created$/i',
        'expires' => '/^expires$/i',
        'changed' => '/^changed$/i',
        'nameserver' => '/^ns[0-9]+$/i',

        // Contacts: Owner
        'contacts:owner:handle' => '/^owner-c:nic-hdl$/i',
        'contacts:owner:name' => '/^owner-c:person$/i',
        'contacts:owner:organization' => '/^owner-c:organi[sz]ation$/i',
        'contacts:owner:address' => '/^owner-c:address$/i',
        'contacts:owner:city' => '/^owner-c:city$/i',
        'contacts:owner:state' => '/^owner-c:state$/i',
        'contacts:owner:zipcode' => '/^owner-c:zipcode$/i',
        'contacts:owner:country' => '/^owner-c:country$/i',
        'contacts:owner:phone' => '/^owner-c:phone$/i',
        'contacts:owner:fax' => '/^owner-c:fax$/i',
        'contacts:owner:email' => '/^owner-c:email$/i',
        'contacts:owner:changed' => '/^owner-c:lastupdated$/i',

        // Contacts: Admin
        'contacts:admin:handle' => '/^admin-c:nic-hdl$/i',
        'contacts:admin:name' => '/^admin-c:person$/i',
        'contacts:admin:organization' => '/^admin-c:organi[sz]ation$/i',
        'contacts:admin:address' => '/^admin-c:address$/i',
        'contacts:admin:city' => '/^admin-c:city$/i',
        'contacts:admin:state' => '/^admin-c:state$/i',
        'contacts:admin:zipcode' => '/^admin-c:zipcode$/i',
        'contacts:admin:country' => '/^admin-c:country$/i',
        'contacts:admin:phone' => '/^admin-c:phone$/i',
        'contacts:admin:fax' => '/^admin-c:fax$/i',
        'contacts:admin:email' => '/^admin-c:email$/i',
        'contacts:admin:changed' => '/^admin-c:lastupdated$/i',

        // Contacts: Tech
        'contacts:tech:handle' => '/^tech-c:nic-hdl$/i',
        'contacts:tech:name' => '/^tech-c:person$/i',
        'contacts:tech:organization' => '/^tech-c:organi[sz]ation$/i',
        'contacts:tech:address' => '/^tech-c:address$/i',
        'contacts:tech:city' => '/^tech-c:city$/i',
        'contacts:tech:state' => '/^tech-c:state$/i',
        'contacts:tech:zipcode' => '/^tech-c:zipcode$/i',
        'contacts:tech:country' => '/^tech-c:country$/i',
        'contacts:tech:phone' => '/^tech-c:phone$/i',
        'contacts:tech:fax' => '/^tech-c:fax$/i',
        'contacts:tech:email' => '/^tech-c:email$/i',
        'contacts:tech:changed' => '/^tech-c:lastupdated$/i',

        // Contacts: Billing
        'contacts:billing:handle' => '/^bill-c:nic-hdl$/i',
        'contacts:billing:name' => '/^bill-c:person$/i',
        'contacts:billing:organization' => '/^bill-c:organi[sz]ation$/i',
        'contacts:billing:address' => '/^bill-c:address$/i',
        'contacts:billing:city' => '/^bill-c:city$/i',
        'contacts:billing:state' => '/^bill-c:state$/i',
        'contacts:billing:zipcode' => '/^bill-c:zipcode$/i',
        'contacts:billing:country' => '/^bill-c:country$/i',
        'contacts:billing:phone' => '/^bill-c:phone$/i',
        'contacts:billing:fax' => '/^bill-c:fax$/i',
        'contacts:billing:email' => '/^bill-c:email$/i',
        'contacts:billing:changed' => '/^bill-c:lastupdated$/i',
    );

    protected $available = array(
        '/^\s*# Not found\s*/im',
    );


    protected function reformatData()
    {
        $dateKeys = array(
            'created', 'changed', 'expires', 'reg_created',
            'admin-c:lastupdated', 'bill-c:lastupdated', 'owner-c:lastupdated', 'tech-c:lastupdated'
        );
        foreach ($dateKeys as $k) {
            if (isset($this->data[$k]) && preg_match('/^[0-9]+$/', $this->data[$k])) {
                $this->data[$k] = date('Y-m-d H:i:s', $this->data[$k]);
            }
        }
    }

}
