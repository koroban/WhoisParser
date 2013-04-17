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
 * Template for Switch Domains .CH / .LI
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Switch extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/holder of domain name:\n(.*?)(?=contractual language)/is', 
            2 => '/technical contact:\n(.*?)(?=dnssec)/is', 3 => '/dnssec:(.*?)(?=name servers)/is', 
            4 => '/name servers:\n(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/holder of domain name:\n(.*)$/is' => 'contacts:owner:address'), 
            2 => array('/technical contact:\n(.*?)$/is' => 'contacts:tech:address'), 
            3 => array('/dnssec:(?>[\x20\t]*)(.+)$/im' => 'dnssec'), 
            4 => array('/\n(?>[\x20\t]*)(.+)$/im' => 'nameserver', 
                    '/\n(?>[\x20\t]*)(.+)(?>[\x20\t]*)\[.+\]$/im' => 'nameserver', 
                    '/\n(?>[\x20\t]*).+(?>[\x20\t]*)\[(.+)\]$/im' => 'ips'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/We do not have an entry in our database matching your query/i';

    /**
     * After parsing ...
     * 
     * Fix contact addresses and set dnssec
     * 
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        if ($ResultSet->dnssec === 'Y') {
            $ResultSet->dnssec = true;
        } else {
            $ResultSet->dnssec = false;
        }
        
        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                $filteredAddress = array_map('trim', explode("\n", trim($contactObject->address)));
                
                switch (sizeof($filteredAddress)) {
                    case 6:
                        $contactObject->organization = $filteredAddress[0];
                        $contactObject->name = $filteredAddress[1];
                        $contactObject->country = $filteredAddress[5];
                        $contactObject->city = $filteredAddress[4];
                        $contactObject->address = $filteredAddress[3];
                        break;
                    default:
                        $contactObject->organization = $filteredAddress[0];
                        $contactObject->name = $filteredAddress[1];
                        $contactObject->country = $filteredAddress[4];
                        $contactObject->city = $filteredAddress[3];
                        $contactObject->address = $filteredAddress[2];
                        break;
                }
            }
        }
    }
}