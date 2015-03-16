<?php

namespace Novutec\WhoisParser\Templates;

use Novutec\WhoisParser\Templates\Type\Regex;

class Chinanet extends Regex
{
    /**
     * Blocks within the raw output of the whois
     *
     * @var array
     * @access protected
     */
    protected $blocks = array(
        1 => '/Domain Name:(.*?)\n\n/is',
        2 => '/Registrant Contact:(.*?)\n\n/is',
        3 => '/Administrative Contact:(.*?)\n\n/is',
        4 => '/Technical Contact:(.*?)\n\n/is',
        5 => '/Billing Contact:(.*?)(\n\n|$)/is',
    );

    /**
     * Items for each block
     *
     * @var array
     * @access protected
     */
    protected $blockItems = array(
        1 => array(
            '/Domain Name:(?>[\x20\t]*)(.+)/im' => 'name',
            '/Registrar:(?>[\x20\t]*)(.+)/im' => 'registrar:name',
            '/Creation Date:(?>[\x20\t]*)(.+)/im' => 'created',
            '/Expiration Date:(?>[\x20\t]*)(.+)/im' => 'expires',
            '/Name Server:(?>[\x20\t]*)(.+)/im' => 'nameserver',
        ),
        2 => array('/Registrant Contact:\n(?>[\x20\t]*)(.+)/is' => 'contacts:owner:address'),
        3 => array('/Administrative Contact:\n(?>[\x20\t]*)(.+)/is' => 'contacts:admin:address'),
        4 => array('/Technical Contact:\n(?>[\x20\t]*)(.+)/is' => 'contacts:tech:address'),
        5 => array('/Billing Contact:\n(?>[\x20\t]*)(.+)/is' => 'contacts:billing:address'),
    );

    /**
     * After parsing do something
     *
     * Fix addresses
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();

        if (isset($ResultSet->nameserver)) {
            if ((!is_array($ResultSet->nameserver)) && strlen($ResultSet->nameserver)) {
                $ResultSet->nameserver = array($ResultSet->nameserver);
            }

            if (is_array($ResultSet->nameserver) && (count($ResultSet->nameserver) == 1)) {
                $ResultSet->nameserver = explode(',', $ResultSet->nameserver[0]);
            }
        }

        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                $filteredAddress = array_map('trim', explode("\n", trim($contactObject->address)));

                $nameLine = array_shift($filteredAddress);
                preg_match('/(?>[\x20\t]*)(.*)(?>[\x20\t]{1,})(.*@.*)/i', $nameLine, $matches);

                if (sizeof($matches) === 0) {
                    $contactObject->name = $nameLine;
                } else {
                    if (isset($matches[1])) {
                        $contactObject->name = trim($matches[1]);
                    }

                    if (isset($matches[2])) {
                        $contactObject->email = trim($matches[2]);
                    }
                }

                foreach ($filteredAddress as $i => $line) {
                    $matches = array();
                    if (preg_match('/^telephone: (.*)$/i', $line, $matches)) {
                        $contactObject->phone = $matches[1];
                        unset($filteredAddress[$i]);
                    } else if (preg_match('/^fax: (.*)$/i', $line, $matches)) {
                        $contactObject->fax = $matches[1];
                        unset($filteredAddress[$i]);
                    }
                }
                $contactObject->address = $filteredAddress;
            }
        }
    }

}