<?php

namespace Novutec\WhoisParser\Templates;

use Novutec\WhoisParser\Templates\Type\KeyValue;

class Govza extends KeyValue
{
    protected $regexKeys = array(
        'name' => '/^[0-9]+[a-z]+\.\s*Domain Name$/i',
        'changed' => '/^[0-9]+[a-z]+\.\s*Date$/i',
        'nameserver' => '/^[0-9]+[a-z]+\.\s*(Primary|Secondary) NS$/i',

        // Contacts: Owner
        'contacts:owner:name' => '/^[0-9]+[a-z]+\.\s*Name of Applicant$/i',
        'contacts:owner:organization' => '/^[0-9]+[a-z]+\.\s*Department Name$/i',
        'contacts:owner:address' => '/^2[a-z]+\.\s*Postal Address$/i',
        'contacts:owner:zipcode' => '/^2[a-z]+\.\s*Postal Code$/i',

        // Contacts: Admin
        'contacts:admin:name' => '/^[0-9]+[a-z]+\.\s*Admin Contact Name$/i',
        'contacts:admin:position' => '/^3[a-z]+\.\s*Title\\\\Position$/i',
        'contacts:admin:organization' => '/^3[a-z]+\.\s*Department$/i',
        'contacts:admin:address' => '/^3[a-z]+\.\s*Postal Address$/i',
        'contacts:admin:zipcode' => '/^3[a-z]+\.\s*Postal Code$/i',
        'contacts:admin:phone' => '/^3[a-z]+\.\s*Telephone$/i',
        'contacts:admin:fax' => '/^3[a-z]+\.\s*Fax$/i',
        'contacts:admin:mobile' => '/^3[a-z]+\.\s*Cell Phone$/i',
        'contacts:admin:email' => '/^3[a-z]+\.\s*Email$/i',

        // Contacts: Tech
        'contacts:tech:name' => '/^[0-9]+[a-z]+\.\s*Tech Contact Name$/i',
        'contacts:tech:position' => '/^4[a-z]+\.\s*Title\\\\Position$/i',
        'contacts:tech:organization' => '/^4[a-z]+\.\s*Department$/i',
        'contacts:tech:address' => '/^4[a-z]+\.\s*Postal Address$/i',
        'contacts:tech:zipcode' => '/^4[a-z]+\.\s*Postal Code$/i',
        'contacts:tech:phone' => '/^4[a-z]+\.\s*Telephone$/i',
        'contacts:tech:fax' => '/^4[a-z]+\.\s*Fax$/i',
        'contacts:tech:mobile' => '/^4[a-z]+\.\s*Cell Phone$/i',
        'contacts:tech:email' => '/^4[a-z]+\.\s*Email$/i',
    );

    protected $available = '/^No match found for /im';
}
