<?php

namespace Novutec\WhoisParser\Templates;

use Novutec\WhoisParser\Templates\Type\Regex;

/**
 * Java Whois Server 0.3.2.2    ... Klaus Zerwes zero-sys.net
 */
class Zerosys extends Regex {

    protected $blocks = array(
        0 => '/Domain:(?>[\x20\t]*)(.*?)\[[a-z0-9\_]+\]/ims',
        1 => '/\[registrar\](.*?)(\[[a-z0-9\_]+\])/ims',
        2 => '/\[holder\](.*?)(\[[a-z0-9\_]+\])/ims',
        3 => '/\[admin_c\](.*?)(\[[a-z0-9\_]+\])/ims',
        4 => '/\[tech_c\](.*)/ims',
    );

    protected $blockItems = array(
        0 => array(
            '/Domain:\s*(.*)$/im' => 'name',
            '/Updated Date:\s*(.*)$/im' => 'changed',
            '/Creation Date:\s*(.*)$/im' => 'created',
            '/Expiration Date:\s*(.*)$/im' => 'expires',
        ),
        1 => array(
            '/Registrar:\s*(.*)$/im' => 'registrar:name',
        ),
        2 => array(
            '/name:\s*(.*)$/im' => 'contacts:owner:name',
            '/address:\s*(.*)$/im' => 'contacts:owner:address',
            '/city:\s*(.*)$/im' => 'contacts:owner:city',
            '/pcode:\s*(.*)$/im' => 'contacts:owner:zipcode',
            '/country:\s*(.*)$/im' => 'contacts:owner:country',
            '/phone:\s*(.*)$/im' => 'contacts:owner:phone',
            '/fax:\s*(.*)$/im' => 'contacts:owner:fax',
            '/email:\s*(.*)$/im' => 'contacts:owner:email',
            '/changed:\s*(.*)$/im' => 'contacts:owner:changed',
        ),
        3 => array(
            '/name:\s*(.*)$/im' => 'contacts:admin:name',
            '/address:\s*(.*)$/im' => 'contacts:admin:address',
            '/city:\s*(.*)$/im' => 'contacts:admin:city',
            '/pcode:\s*(.*)$/im' => 'contacts:admin:zipcode',
            '/country:\s*(.*)$/im' => 'contacts:admin:country',
            '/phone:\s*(.*)$/im' => 'contacts:admin:phone',
            '/fax:\s*(.*)$/im' => 'contacts:admin:fax',
            '/email:\s*(.*)$/im' => 'contacts:admin:email',
            '/changed:\s*(.*)$/im' => 'contacts:admin:changed',
        ),
        4 => array(
            '/name:\s*(.*)$/im' => 'contacts:tech:name',
            '/address:\s*(.*)$/im' => 'contacts:tech:address',
            '/city:\s*(.*)$/im' => 'contacts:tech:city',
            '/pcode:\s*(.*)$/im' => 'contacts:tech:zipcode',
            '/country:\s*(.*)$/im' => 'contacts:tech:country',
            '/phone:\s*(.*)$/im' => 'contacts:tech:phone',
            '/fax:\s*(.*)$/im' => 'contacts:tech:fax',
            '/email:\s*(.*)$/im' => 'contacts:tech:email',
            '/changed:\s*(.*)$/im' => 'contacts:tech:changed',
        ),
    );


    public function postProcess(&$WhoisParser)
    {
        $result = $WhoisParser->getResult();
        if (isset($result->registrar->name) && strlen($result->registrar->name)) {
            $nameParts = explode(' - ', $result->registrar->name, 2);
            if (count($nameParts) == 2) {
                $result->registrar->name = trim($nameParts[0]);
                $result->registrar->url = trim($nameParts[1]);
            }
        }
    }
}