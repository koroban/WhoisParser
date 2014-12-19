<?php

namespace Novutec\WhoisParser\Templates;

use Novutec\WhoisParser\Templates\Type\Regex;

class Dyndns extends Regex {

    protected $blocks = array(
        0 => '/registrant:\s*(.*?)(?=domain name:)/is',
        1 => '/domain name:\s*(.*)$/im',
        2 => '/administrative contact, technical contact:\s*(.*?)(?=\s*registration service provider:)/ims',
        3 => '/administrative contact:\s*(.*?)(?=\s*technical contact:)/ims',
        4 => '/technical contact:\s*(.*?)(?=\s*registration service provider:)/ims',
        5 => '/registration service provider:\s*(.*?)(?=\s*record last updated on)/ims',
        6 => '/record last updated on(.*)/ims',
    );

    protected $blockItems = array(
        0 => array(
            '/registrant:\s*(.*)/is' => 'contacts:owner:address'
        ),
        1 => array(
            '/domain name:\s*(.*)$/im' => 'name'
        ),
        2 => array(
            '/ contact:\n(.*?)$/is' => 'contacts:admin:address',
        ),
        3 => array(
            '/ contact:\n(.*?)$/is' => 'contacts:admin:address',
        ),
        4 => array(
            '/ contact:\n(.*?)$/is' => 'contacts:tech:address',
        ),
        5 => array(
            '/registration service provider:\s*(.*)/is' => 'registrar:name',
        ),
        6 => array(
            '/record last updated on (.*?)[\.]?$/im' => 'changed',
            '/record expires on (.*?)[\.]?$/im' => 'expires',
            '/record created on (.*?)[\.]?$/im' => 'created',
            '/domain servers in listed order:\s*(.*?)\s*domain status:/ims' => 'nameserver',
            '/domain status:\s*(.*)/ims' => 'status',
        ),
    );


    public function postProcess(&$WhoisParser)
    {
        $result = $WhoisParser->getResult();

        if (isset($result->registrar->name)) {
            $name = $result->registrar->name;
            if (is_array($name)) {
                $name = join("\n", $name);
            }
            $name = str_replace(array("\r\n", "\r"), "\n", $name);
            $nameLines = explode("\n", $name);
            $name = array_shift($nameLines);
            $nameParts = explode('  ', $name);
            if (count($nameParts) > 1) {
                $result->registrar->email = array_pop($nameParts);
                $result->registrar->name = join('  ', $nameParts);
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

                    // Does the last line look like a phone number?
                    $last = array_pop($filteredAddress);
                    if (preg_match('/^\+[0-9\ \.\-\(\)]+$/', $last)) {
                        $contactObject->phone = $last;
                    } else {
                        $filteredAddress[] = $last;
                    }

                    // Does the first line contain an email address too?
                    $name = array_shift($filteredAddress);
                    $nameParts = explode('  ', $name);
                    if (count($nameParts) > 1) {
                        $contactObject->email = array_pop($nameParts);
                        $contactObject->name = join('  ', $nameParts);
                    } else {
                        $contactObject->name = $name;
                    }

                    // Dyn appears to use a "lastname, firstname" format
                    $name = $contactObject->name;
                    $nameParts = explode(', ', $name);
                    if (count($nameParts) == 2) {
                        $name = $nameParts[1] .' '. $nameParts[0];
                    }
                    $contactObject->name = $name;

                    $contactObject->address = $filteredAddress;
                }
            }
        }
    }
}
