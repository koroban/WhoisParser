<?php

namespace Novutec\WhoisParser\Templates;

use Novutec\WhoisParser\Templates\Type\Regex;

class Domainregistry extends Regex
{
    protected $blocks = array(
        1 => '/^\s*Registrant:(.*?)\n\n/ims',
        2 => '/^\s*Registrar Name\.*:(.*?)\n\n/ims',
        3 => '/^\s*Domain Name:[^\n]+\n\n(.*?)\n\n/ims',
        4 => '/Administrative(_| )contact(.*?)\n\n/ims',
        5 => '/Billing(_| )contact(.*?)\n\n/ims',
        6 => '/Technical(_| )contact(.*?)\n\n/ims',
        7 => '/Zone(_| )contact(.*?)\n\n/ims',
        8 => '/^\s*Domain servers in listed order:\n\n(.*?)\n\n/ims',
    );


    protected $blockItems = array(
        1 => array(
            '/^\s*Registrant:(.*)/ims' => 'contacts:owner:address',
        ),
        2 => array(
            '/^\s*Registrar Name\.*:(.*)/im' => 'registrar:name',
            '/^\s*Registrar Whois\.*:(.*)/im' => 'ask_whois',
            '/^\s*Registrar Homepage\.*:(.*)/im' => 'registrar:url',
        ),
        3 => array(
            '/^\s*Domain Name:(.*)/im' => 'name',
            '/^\s*Created on\.*:(.*)/im' => 'created',
            '/^\s*Expires on\.*:(.*)/im' => 'expires',
            '/^\s*Record last updated on\.*:(.*)/im' => 'changed',
        ),
        4 => array(
            '/contact:\n(.*)/ims' => 'contacts:admin:address',
        ),
        5 => array(
            '/contact:\n(.*)/ims' => 'contacts:billing:address',
        ),
        6 => array(
            '/contact:\n(.*)/ims' => 'contacts:tech:address',
        ),
        7 => array(
            '/contact:\n(.*)/ims' => 'contacts:zone:address',
        ),
        8 => array(
            '/^\s*[^\s\.]+\.[^\s]+$/im' => 'nameserver',
        ),
    );

    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();

        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                $filteredAddress = $contactObject->address;
                if (!is_array($filteredAddress)) {
                    $filteredAddress = explode("\n", $filteredAddress);
                }
                $contactObject->name = trim(array_shift($filteredAddress));

                foreach ($filteredAddress as $i => $line) {
                    $line = trim($line);
                    $matches = array();

                    if (preg_match('/^phone:(.*)$/im', $line, $matches)) {
                        $contactObject->phone = trim($matches[1]);
                        unset($filteredAddress[$i]);
                        continue;
                    }
                    if (preg_match('/^email:(.*)$/im', $line, $matches)) {
                        $contactObject->email = trim($matches[1]);
                        unset($filteredAddress[$i]);
                        continue;
                    }
                    if (preg_match('/^fax:(.*)$/im', $line, $matches)) {
                        $contactObject->fax = trim($matches[1]);
                        unset($filteredAddress[$i]);
                        continue;
                    }
                }

                $contactObject->address = $filteredAddress;
            }
        }
    }
}