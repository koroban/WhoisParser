<?php

namespace Novutec\WhoisParser\Templates;

use Novutec\WhoisParser\Templates\Type\KeyValue;

class To extends KeyValue {

    protected $kvSeparator = ' ';

    protected $regexKeys = array();

    protected $available = '/^No match for .+$/im';


    /**
     * @param \Novutec\WhoisParser\Result\Result $previousResult
     * @param $rawdata
     * @param string|object $query
     * @throws \Novutec\WhoisParser\Exception\ReadErrorException if data was read from the whois response
     */
    public function parse($previousResult, $rawdata, $query)
    {
        $domain = (is_object($query) ? $query->domain : $query);
        if (stripos($domain, '.to') == (strlen($domain) - 2)) {
            $domain = substr($domain, 0, -3);
        }
        $this->regexKeys['nameserver'] = '/^'. preg_quote($domain) .'$/i';

        parent::parse($previousResult, $rawdata, $query);
    }
}
