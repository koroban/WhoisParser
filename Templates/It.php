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
 * Template for .IT
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_It extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Domain:(?>[\x20\t]*)(.*?)(?=Registrant)/is', 
            2 => '/Registrant(?>[\x20\t]*)(.*?)(?=Admin Contact)/is', 
            3 => '/Admin Contact(?>[\x20\t]*)(.*?)(?=Technical Contacts)/is', 
            4 => '/Technical Contacts(?>[\x20\t]*)(.*?)(?=Registrar)/is', 
            5 => '/Registrar(?>[\x20\t]*)(.*?)(?=Nameservers)/is', 
            6 => '/Nameservers(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/status:(?>[\x20\t]*)(.+)$/im' => 'status', 
                    '/created:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/^Last Update:(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/^Expire Date:(?>[\x20\t]*)(.+)$/im' => 'expires'), 
            2 => array('/Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/Organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization', 
                    '/ContactID:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:handle', 
                    '/Address:(?>[\x20\t]*)(.+)(?=Created)/is' => 'contacts:owner:address', 
                    '/Created:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:created', 
                    '/Last Update:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:changed'), 
            3 => array('/Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/Organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:organization', 
                    '/ContactID:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:handle', 
                    '/Address:(?>[\x20\t]*)(.+)(?=Created)/is' => 'contacts:admin:address', 
                    '/Created:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:created', 
                    '/Last Update:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:changed'), 
            4 => array('/Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/Organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:organization', 
                    '/ContactID:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:handle', 
                    '/Address:(?>[\x20\t]*)(.+)(?=Created)/is' => 'contacts:tech:address', 
                    '/Created:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:created', 
                    '/Last Update:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:changed'), 
            5 => array('/Organization:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/Name:(?>[\x20\t]*)(.+)$/im' => 'registrar:id'), 
            6 => array('/Nameservers[\n](?>[\x20\t]*)(.+)$/is' => 'nameserver'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/Status:(?>[\x20\t]*)AVAILABLE/i';

    /**
     * After parsing ...
     *
     * Fix address and nameserver in whois output
     *
     * @param  object $whoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        $filteredNameserver = array();
        
        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                if (! is_array($contactObject->address)) {
                    $explodedAddress = explode("\n", $contactObject->address);
                    
                    $contactObject->address = trim($explodedAddress[0]);
                    $contactObject->city = trim($explodedAddress[1]);
                    $contactObject->zipcode = trim($explodedAddress[2]);
                    $contactObject->state = trim($explodedAddress[3]);
                    $contactObject->country = trim($explodedAddress[4]);
                }
            }
        }
        
        if (isset($ResultSet->nameserver) && $ResultSet->nameserver != '' &&
                 ! is_array($ResultSet->nameserver)) {
            $explodedNameserver = explode("\n", $ResultSet->nameserver);
            foreach ($explodedNameserver as $key => $line) {
                if (trim($line) != '') {
                    $filteredNameserver[] = strtolower(trim($line));
                }
            }
            $ResultSet->nameserver = $filteredNameserver;
        }
    }
}