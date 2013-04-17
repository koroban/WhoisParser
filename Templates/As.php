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
 * Template for .AS
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_As extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Registered by:(?>[\x20\t]*)(.*?)(?=Nameservers:)/is', 
            2 => '/Nameservers:(?>[\x20\t]*)(.*?)(?=Access to ASNIC)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/Registered by:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name'), 
            2 => array('/Nameservers:(?>[\x20\t]*)(.+)$/is' => 'nameserver'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/Domain Not Found/i';

    /**
     * After parsing ...
     *
     * Fix nameserver and IP addresses in WHOIS output
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        $filteredNameserver = array();
        $filteredIps = array();
        
        if ($ResultSet->nameserver != '') {
            $explodedNameserver = array_map('trim', explode("\n", trim($ResultSet->nameserver)));
            
            foreach ($explodedNameserver as $line) {
                preg_match('/(.+) \((.+)\)$/im', $line, $matches);
                $filteredNameserver[] = $matches[1];
                $filteredIps[] = $matches[2];
            }
            
            $ResultSet->nameserver = $filteredNameserver;
            $ResultSet->ips = $filteredIps;
        }
    }
}