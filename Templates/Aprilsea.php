<?php

namespace Novutec\WhoisParser\Templates;

use Novutec\WhoisParser\Templates\Type\Regex;

class Aprilsea extends Regex {

    protected $blocks = array(
        0 => '/Registrant:\s*(.*?)Domain Name:/ims',
        1 => '/Domain Name:\s*(.*)$/im',
        2 => '/Administrative Contact:\s*(.*?)Technical Contact:/ims',
        3 => '/Technical Contact:\s*(.*?)Records expires on/ims',
        4 => '/Record expires on(.*)/ims',
    );

    protected $blockItems = array(
        0 => array(
            '/Registrant:(.*?)Email:/ims' => 'contacts:owner:address',
            '/Email:\s*(.*)$/im' => 'contacts:owner:email',
            '/Phone:\s*(.*)$/im' => 'contacts:owner:phone',
            '/Fax:\s*(.*)$/im' => 'contacts:owner:fax',
        ),
        1 => array(
            '/Domain Name:\s*(.*)$/im' => 'name',
        ),
        2 => array(
            '/ Contact:(.*?)Email:/ims' => 'contacts:admin:address',
            '/Email:\s*(.*)$/im' => 'contacts:admin:email',
            '/Phone:\s*(.*)$/im' => 'contacts:admin:phone',
            '/Fax:\s*(.*)$/im' => 'contacts:admin:fax',
        ),
        3 => array(
            '/ Contact:(.*?)Email:/ims' => 'contacts:tech:address',
            '/Email:\s*(.*)$/im' => 'contacts:tech:email',
            '/Phone:\s*(.*)$/im' => 'contacts:tech:phone',
            '/Fax:\s*(.*)$/im' => 'contacts:tech:fax',
        ),
        4 => array(
            '/Record expires on (.*)$/im' => 'expires',
            '/Record created on (.*)$/im' => 'created',
            '/Database last updated on (.*)$/im' => 'changed',
            '/Domain Servers:\s*(.*)/ims' => 'nameserver',
        ),
    );


    public function postProcess(&$WhoisParser)
    {
        $result = $WhoisParser->getResult();

        $ns = $result->nameserver;
        $filteredNs = array();
        if (is_string($ns)) {
            $ns = explode("\n", trim($ns));
        }
        if (is_array($ns)) {
            foreach ($ns as $server) {
                $server = trim($server);
                if (strlen($server)) {
                    $filteredNs[] = $server;
                }
            }
        }
        $result->nameserver = $filteredNs;

        foreach ($result->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                $filteredAddress = array();

                if (! is_array($contactObject->address)) {
                    $explodedAddress = explode("\n", trim($contactObject->address));

                    foreach ($explodedAddress as $key => $line) {
                        $filteredAddress[] = trim($line);
                    }

                    $contactObject->name = array_shift($filteredAddress);
                    $contactObject->address = $filteredAddress;
                }
            }
        }
    }
}
