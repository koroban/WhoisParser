<?php

namespace Novutec\WhoisParser\Templates;

use Novutec\WhoisParser\Templates\Type\IndentedBlocks;

class Janet extends IndentedBlocks
{
    protected $regexKeys = array(
        'name' => '/^Domain$/i',
        'created' => '/^Entry created$/i',
        'expires' => '/^Renewal date$/i',
        'changed' => '/^Entry updated$/i',
        'nameserver' => '/^Servers$/i',

        // Contacts: Owner
        'contacts:owner:name' => '/^Registrant Contact$/i',
        'contacts:owner:organization' => '/^Registered For$/i',
        'contacts:owner:address' => '/^Registrant Address$/i',
    );

    protected $available = '/^\s*No such domain (.*)\s*/is';


    public function postProcess(&$WhoisParser)
    {
        $result = $WhoisParser->getResult();

        if (isset($result->nameserver) && strlen($result->nameserver)) {
            $serverList = explode("\n", $result->nameserver);
            foreach ($serverList as $i => $server) {
                $serverParts = explode("\t", $server);
                $serverList[$i] = $serverParts[0];
            }
            $result->nameserver = array_unique($serverList);
        }

        foreach ($result->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                $unfilteredAddress = explode("\n", $contactObject->address);

                $lastLine = array_pop($unfilteredAddress);
                if (preg_match('/^\s*.+@.+\..+\s*$/i', $lastLine)) {
                    $contactObject->email = $lastLine;
                } else {
                    $unfilteredAddress[] = $lastLine;
                }

                $lastLine = array_pop($unfilteredAddress);
                if (preg_match('/ \(FAX\)\s*$/i', $lastLine)) {
                    $contactObject->fax = preg_replace('/ \(FAX\)\s*$/i', '', $lastLine);
                } else {
                    $unfilteredAddress[] = $lastLine;
                }

                $lastLine = array_pop($unfilteredAddress);
                if (preg_match('/ \(Phone\)\s*$/i', $lastLine)) {
                    $contactObject->phone = preg_replace('/ \(Phone\)\s*$/i', '', $lastLine);
                } else {
                    $unfilteredAddress[] = $lastLine;
                }

                $contactObject->address = $unfilteredAddress;
            }
        }
    }
}
