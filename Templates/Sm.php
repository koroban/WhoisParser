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
 * Template for .SM
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Sm extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Domain Name(?>[\x20\t]*):(?>[\x20\t]*)(.*?)(?=Owner)/is', 
            2 => '/Owner(?>[\x20\t]*):\n(?>[\x20\t]*)(.*?)(?=Technical Contact)/is', 
            3 => '/Technical Contact(?>[\x20\t]*):\n(?>[\x20\t]*)(.*?)(?=DNS Servers)/is', 
            4 => '/DNS Servers(?>[\x20\t]*):\n(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/Registration date(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/Last Update(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/Status(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'status'), 
            2 => array(
                    '/Owner(?>[\x20\t]*):\n(?>[\x20\t]*)(.+)(?=Phone)/is' => 'contacts:owner:address', 
                    '/Phone(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:phone', 
                    '/Fax(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:fax', 
                    '/Email(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:email'), 
            3 => array(
                    '/Technical Contact(?>[\x20\t]*):\n(?>[\x20\t]*)(.+)(?=Phone)/is' => 'contacts:tech:address', 
                    '/Phone(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/Fax(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:fax', 
                    '/Email(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email'), 
            4 => array('/DNS Servers(?>[\x20\t]*):\n(?>[\x20\t]*)(.+)$/is' => 'nameserver'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No entries found./i';

    /**
     * After parsing do something
     *
     * Fix address
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        $filteredNameserver = array();
        $filteredAddress = array();
        
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
        
        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                $filteredAddress = array_map('trim', explode("\n", trim($contactObject->address)));
                
                $contactObject->name = $filteredAddress[0];
                $contactObject->organization = $filteredAddress[1];
                $contactObject->address = $filteredAddress[2];
                $contactObject->city = $filteredAddress[3];
                $contactObject->country = $filteredAddress[4];
            }
        }
    }
}