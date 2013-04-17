<?php
/**
 * Novutec Domain Tools
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @category   Novutec
 * @package    DomainParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * @namespace Novutec\WhoisParser
 */
namespace Novutec\WhoisParser;

/**
 * Template for IANA
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Iana extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/whois:(?>[\x20\t]*)(.*?)[\n]{2}/is', 
            2 => '/domain:(?>[\x20\t]*)(.*?)[\n]{2}/is', 
            3 => '/organisation:(?>[\x20\t]*)(.*?)(?=contact:(?>[\x20\t]*)administrative)/is', 
            4 => '/contact:(?>[\x20\t]*)administrative(.*?)(?=contact:(?>[\x20\t]*)technical)/is', 
            5 => '/contact:(?>[\x20\t]*)technical(.*?)(?=nserver)/is', 
            6 => '/nserver:(?>[\x20\t]*)(.*?)(?=created)/is', 7 => '/created:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(1 => array('/^whois:(?>[\x20\t]*)(.+)$/im' => 'whoisserver'), 
            2 => array('/^domain:(?>[\x20\t]*)(.+)$/im' => 'name'), 
            3 => array('/organisation:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization', 
                    '/address:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address'), 
            4 => array('/organisation:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:organization', 
                    '/address:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:address', 
                    '/phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone', 
                    '/fax-no:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:fax', 
                    '/e-mail:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:email'), 
            5 => array('/organisation:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:organization', 
                    '/address:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:address', 
                    '/phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/fax-no:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:fax', 
                    '/e-mail:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email'), 
            6 => array('/nserver:(?>[\x20\t]*)(.+) .+ .+$/im' => 'nameserver', 
                    '/nserver:(?>[\x20\t]*).+ (.+) .+$/im' => 'ips', 
                    '/ds-rdata:(?>[\x20\t]*)(.+)$/im' => 'dnssec'), 
            7 => array('/created:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/changed:(?>[\x20\t]*)(.+)$/im' => 'changed'));

    /**
     * After parsing do something
     * 
     * If result contains domain then we have to ask a domain name registry for
     * the full and correct whois output about the domain name.
     * 
     * If result contains only whois server and not domain then we have to ask
     * a RIR for the full and correct whois output about the IP address.
     * 
     * If result is just a top-level domain name we are stopping the processing
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $Result = $WhoisParser->getResult();
        $Config = $WhoisParser->getConfig();
        $Query = $WhoisParser->getQuery();
        
        if ($Result->dnssec != '') {
            $Result->dnssec = true;
        } else {
            $Result->dnssec = false;
        }
        
        if (isset($Query->idnFqdn) || isset($Query->ip) || isset($Query->asn)) {
            if (isset($Result->name) && $Result->name != '') {
                if ($Result->name !== $Query->tld) {
                    $newConfig = $Config->get($Query->tld);
                }
                
                if ($Result->name === $Query->tld || $newConfig['dummy'] === false) {
                    $newConfig = $Config->get($Result->name);
                }
                
                if ($newConfig['server'] == '') {
                    $newConfig['server'] = $Result->whoisserver;
                }
            } else {
                $mapping = $Config->get($Result->whoisserver);
                $newConfig = $Config->get($mapping['template']);
            }
            
            if ($newConfig['server'] != '') {
                $Result->reset();
                $Config->setCurrent($newConfig);
                $WhoisParser->call();
            }
        }
    }
}