<?php

namespace Novutec\WhoisParser\Templates;

use Novutec\WhoisParser\Templates\Type\Regex;

class Netpia extends Regex {

    protected $blocks = array(
        0 => '/\#\s*ENGLISH(.*?)\#\s*KOREAN/ims',
    );

    protected $blockItems = array(
        0 => array(
            '/Registrant\s*:\s*(.*?)Domain Name\s*:/ims' => 'contacts:owner:address',
            '/Domain Name\s*:\s*(.*)$/im' => 'name',
            '/Registrar\s*:\s*(.*)$/im' => 'registrar:name',
            '/Administrative Contact\s*:\s*(.*?)Technical Contact\s*:/ims' => 'contacts:admin:address',
            '/Technical Contact\s*:\s*(.*?)Billing Contact\s*:/ims' => 'contacts:tech:address',
            '/Billing Contact\s*:\s*(.*?)Record created\s*:/ims' => 'contacts:billing:address',
            '/Record created on[\s\.]*:\s*(.*)$/im' => 'created',
            '/Record expires on[\s\.]*:\s*(.*)$/im' => 'expires',
            '/Record last updated on[\s\.]*:\s*(.*)$/im' => 'changed',
            '/Domain name servers in listed order\s*:\s*(.*)\#\s*KOREAN/im' => 'nameserver',
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
                            $nameEmailParts = explode("\t", $nameEmail);
                            $contactObject->name = array_shift($nameEmailParts);
                            if (count($nameEmailParts)) {
                                $contactObject->email = array_shift($nameEmailParts);
                            }
                            $contactObject->phone = array_pop($filteredAddress);
                            $contactObject->address = $filteredAddress;
                            break;
                    }
                }
            }
        }
    }
}
