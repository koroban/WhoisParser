<?php

namespace Novutec\WhoisParser\Templates;

use Novutec\WhoisParser\Templates\Type\Regex;

class Domainca extends Regex {
    protected $blocks = array(
        0 => '/^(.*)$/ims',
    );

    protected $blockItems = array(
        0 => array(
            '/Registrant\s*:\s*(.*?)(?=Administrative)/ims' => 'contacts:owner:address',
            '/Domain Name\s*:\s*(.*)$/im' => 'name',
            '/Domain Status:\s*(.*)$/im' => 'status',
            '/Registrar\s*:\s*(.*)$/im' => 'registrar:name',
            '/Referral URL:\s*(.*)$/im' => 'registrar:url',
            '/Administrative, Technical, Billing Contact\s*:\s*(.*?)(?=Domain Registration Date)/ims' => 'contacts:admin:address',
            '/Domain Registration Date[\s\.]*:\s*(.*?)\.?$/im' => 'created',
            '/Domain Expiration Date[\s\.]*:\s*(.*?)$\.?/im' => 'expires',
            '/Domain Last Updated Date[\s\.]*:\s*(.*?)\.?$/im' => 'changed',
            '/Domain name servers in listed order\s*:\s*(.*?)(?=If a customer)/ims' => 'nameserver',
        ),
    );


    public function postProcess(&$WhoisParser)
    {
        $result = $WhoisParser->getResult();

        if (isset($result->registrar->name) && strlen($result->registrar->name)) {
            $nameParts = explode('(', $result->registrar->name);
            if (count($nameParts) > 1) {
                $url = rtrim(array_pop($nameParts), ") \t");
                $name = join('(', $nameParts);

                $result->registrar->name = trim($name);
                $result->registrar->url = trim($url);
            }
        }

        foreach ($result->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                $filteredAddress = array();

                if (! is_array($contactObject->address)) {
                    $explodedAddress = explode("\n", trim($contactObject->address));

                    foreach ($explodedAddress as $key => $line) {
                        $filteredAddress[] = trim($line);
                    }

                    switch ($contactType) {
                        case 'owner':
                            $contactObject->organization = array_shift($filteredAddress);
                            $contactObject->address = $filteredAddress;
                            break;

                        default:
                            $nameEmail = array_shift($filteredAddress);
                            $nameEmailParts = explode("   ", $nameEmail);
                            $contactObject->name = array_shift($nameEmailParts);
                            if (count($nameEmailParts)) {
                                $contactObject->email = array_shift($nameEmailParts);
                            }
                            $contactObject->phone = array_pop($filteredAddress);
                            $contactObject->address = $filteredAddress;
                            break;
                    }
                }


                $phoneParts = explode(',', $contactObject->phone);
                if (count($phoneParts) > 1) {
                    $contactObject->phone = trim(str_ireplace('(tel)', '', $phoneParts[0]));
                    $contactObject->fax = trim(str_ireplace('(fax)', '', $phoneParts[1]));
                }
            }
        }
    }
}
