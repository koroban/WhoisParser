<?php

namespace Novutec\WhoisParser\Templates;

use Novutec\WhoisParser\Templates\Type\Regex;

class Twentytwocn extends Regex {

    protected $blocks = array(
        0 => '/^Domain name:(.*)$/im',
        1 => '/^Registrant Contact:\s*(.*?)\s*Administrative Contact:/ims',
        2 => '/^Administrative Contact:\s*(.*?)\s*Technical Contact:/ims',
        3 => '/^Technical Contact:\s*(.*?)\s*Billing Contact:/ims',
        4 => '/^Billing Contact:\s*(.*?)\s*Name Server:/ims',
        5 => '/^Name Server:(.*)/ims'
    );

    protected $blockItems = array(
        0 => array (
            '/^Domain name:(.*)$/im' => 'name',
        ),
        1 => array(
            '/^Registrant Contact:\s*(.*?)\s*Administrative Contact:/ims' => 'contacts:owner:address',
        ),
        2 => array(
            '/^Administrative Contact:\s*(.*?)\s*Technical Contact:/ims' => 'contacts:admin:address',
        ),
        3 => array(
            '/^Technical Contact:\s*(.*?)\s*Billing Contact:/ims' => 'contacts:tech:address',
        ),
        4 => array(
            '/^Billing Contact:\s*(.*?)\s*Name Server:/ims' => 'contacts:billing:address',
        ),
        5 => array(
            '/^Name Server:\s*(.*)$/im' => 'nameserver',
            '/^Registration Date:\s*(.*)$/im' => 'created',
            '/^Expiration Date:\s*(.*)$/im' => 'expires',
        )
    );


    public function postProcess(&$WhoisParser)
    {
        $result = $WhoisParser->getResult();

        foreach ($result->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                if (! is_array($contactObject->address)) {
                    $explodedAddress = explode("\n", trim($contactObject->address));

                    $filteredAddress = array();
                    foreach ($explodedAddress as $key => $line) {
                        $line = trim($line);

                        $matches = array();
                        if (preg_match('/^\s*tel:(.*)$/i', $line, $matches)) {
                            // Previous line is probably email
                            $emailLine = array_pop($filteredAddress);
                            if (strpos($emailLine, '@') !== false) {
                                $contactObject->email = $emailLine;
                            } else {
                                $filteredAddress[] = $emailLine;
                            }

                            if (count($filteredAddress) > 2) {
                                trigger_error('Unexpected number of entries found before telephone - some data discarded', E_USER_NOTICE);
                            }

                            if (count($filteredAddress) > 1) {
                                $contactObject->organization = array_shift($filteredAddress);
                                if (count($filteredAddress)) {
                                    $contactObject->name = array_shift($filteredAddress);
                                }
                            } else if (count($filteredAddress) > 0) {
                                $contactObject->name = array_shift($filteredAddress);
                            }

                            if (count($matches[1])) {
                                $contactObject->phone = $matches[1];
                            }
                            $filteredAddress = array();
                            continue;
                        } else if (preg_match('/^\s*fax:(.*)$/i', $line, $matches)) {
                            $contactObject->fax = $matches[1];
                            $filteredAddress = array();
                            continue;
                        }

                        $filteredAddress[] = trim($line);
                    }

                    $contactObject->address = $filteredAddress;
                }
            }
        }

    }
}
