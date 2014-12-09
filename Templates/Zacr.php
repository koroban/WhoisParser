<?php

namespace Novutec\WhoisParser\Templates;

use Novutec\WhoisParser\Templates\Type\Regex;

class Zacr extends Regex {

    protected $blocks = array(
        0 => '/Domain Name:\s*(.*?)\s*Registrant:/im',
        1 => '/Registrant:\s*(.*?)Registrar:/ims',
        2 => '/Registrar:\s*(.*?)\s*Relevant Dates:/im',
        3 => '/Relevant Dates:\s*(.*?)\s*Domain Status:/ims',
        4 => '/Domain Status:\s*(.*)/ims',
    );

    protected $blockItems = array(
        0 => array(
            '/Domain Name:\s*(.*?)\s*Registrant:/im' => 'name',
        ),
        1 => array(
            '/Registrant:\s*(.*?)\s*Email:/im' => 'contacts:owner:name',
            '/Email:\s*(.*)$/im' => 'contacts:owner:email',
            '/Tel:\s*(.*)$/im' => 'contacts:owner:phone',
            '/Fax:\s*(.*)$/im' => 'contacts:owner:fax',
            '/Registrant\'s Address:\s*(.*?)\s*Registrar:$/ims' => 'contacts:owner:address',
        ),
        2 => array(
            '/Registrar:\s*(.*?)$/im' => 'registrar:name',
        ),
        3 => array(
            '/Registration Date:\s*(.*)$/im' => 'created',
            '/Renewal Date:\s*(.*)$/im' => 'expires',
        ),
        4 => array(
            '/Domain Status:\s*(.*)/im' => 'status',
            '/Name Servers:\s*(.*?)\s*WHOIS lookup/ims' => 'nameserver',
        ),
    );

    protected $available = '/^\s*Available\s*$/ims';
}
