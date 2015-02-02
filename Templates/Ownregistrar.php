<?php

namespace Novutec\WhoisParser\Templates;

use Novutec\WhoisParser\Templates\Type\Regex;

class Ownregistrar extends Regex
{
    protected $blocks = array(
        0 => '/^\s*Domain:(.*?)\n\nRegistrant Contact Details/ims',
        1 => '/^\s*Registrant Contact Details:(.*?)\n\n/ims',
        2 => '/^\s*Administrative Contact Details:(.*?)\n\n/ims',
        3 => '/^\s*Technical Contact Details:(.*?)\n\n/ims',
        4 => '/^\s*Billing Contact Details:(.*?)\n\n/ims',
        5 => '/^\s*Name Servers:(.*?)Last update of WHOIS/ims',
    );

    protected $blockItems = array(
        0 => array(
            '/^\s*Domain:(.*)/im' => 'name',
            '/^\s*Registrar WHOIS Server:(.*)/im' => 'ask_whois',
            '/^\s*Registrar URL:(.*)/im' => 'registrar:url',
            '/^\s*Registrar IANA ID:(.*)/im' => 'registrar:id',
            '/^\s*Registrar\s*:(.*)/im' => 'registrar:name',
            '/^\s*Registrar Abuse Contact Email:(.*)/im' => 'registrar:email',
            '/^\s*Registrar Abuse Contact Phone:(.*)/im' => 'registrar:phone',
            '/^\s*Creation Date:(.*)/im' => 'created',
            '/^\s*Expiration Date:(.*)/im' => 'expires',
        ),
        1 => array(
            '/Contact Details:(.*)/is' => 'contacts:owner:address',
        ),
        2 => array(
            '/Contact Details:(.*)/is' => 'contacts:admin:address',
        ),
        3 => array(
            '/Contact Details:(.*)/is' => 'contacts:tech:address',
        ),
        4 => array(
            '/Contact Details:(.*)/is' => 'contacts:billing:address',
        ),
        5 => array(
            '/^\s*Name Servers:\n(.*?)\n\n/ims' => 'nameserver',
            '/^\sDNSSEC:(.*)/im' => 'dnssec',
        ),
    );

    protected $available = '/No match for domain "/im';

    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();

        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                $unfilteredAddress = $contactObject->address;
                if (!is_array($unfilteredAddress)) {
                    $unfilteredAddress = explode("\n", $unfilteredAddress);
                }

                $filteredAddress = array();
                foreach ($unfilteredAddress as $i => $line) {
                    $matches = array();
                    if (preg_match('/^\s*Tel No.(.*)/i', $line, $matches)) {
                        $contactObject->phone = $matches[1];
                        continue;
                    }
                    if (preg_match('/^\s*Fax No.(.*)/i', $line, $matches)) {
                        $contactObject->fax = $matches[1];
                        continue;
                    }
                    if (preg_match('/^\s*Email Address:(.*)/i', $line, $matches)) {
                        $contactObject->email = $matches[1];
                        continue;
                    }

                    $filteredAddress[] = trim($line);
                }

                $firstLine = trim(array_shift($filteredAddress));
                $contactObject->name = $firstLine;

                $contactObject->address = $filteredAddress;
            }
        }
    }

}
