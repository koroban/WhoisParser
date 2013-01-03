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
 * Template for .BG
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Bg extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/DOMAIN NAME:(?>[\x20\t]*)(.*?)(?=REGISTRANT:)/is', 
            2 => '/REGISTRANT:(?>[\x20\t]*)(.*?)(?=ADMINISTRATIVE CONTACT:)/is', 
            3 => '/ADMINISTRATIVE CONTACT:(?>[\x20\t]*)(.*?)(?=TECHNICAL CONTACT)/is', 
            4 => '/TECHNICAL CONTACT\(S\):(?>[\x20\t]*)(.*?)(?=NIC handle|NAME SERVER INFORMATION)/is', 
            5 => '/NAME SERVER INFORMATION:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/processed from:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/expires at:(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/registration status:(?>[\x20\t]*)(.+)$/im' => 'status'), 
            2 => array('/REGISTRANT:[\n](?>[\x20\t]*)(.+)/is' => 'contacts:owner:address'), 
            3 => array(
                    '/ADMINISTRATIVE CONTACT:[\n](?>[\x20\t]*)(.+)(?=tel:)/is' => 'contacts:admin:address', 
                    '/tel:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone', 
                    '/fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:fax', 
                    '/NIC handle:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:handle'), 
            4 => array(
                    '/TECHNICAL CONTACT\(S\):[\n](?>[\x20\t]*)(.+)(?=tel:)/is' => 'contacts:tech:address', 
                    '/tel:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:fax', 
                    '/NIC handle:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:handle'), 
            5 => array(
                    '/NAME SERVER INFORMATION:[\r\n](?>[\x20\t]*)(.*)(?=DNSSEC)/is' => 'nameserver', 
                    '/DNSSEC:(?>[\x20\t]*)(.+)$/im' => 'dnssec'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/does not exist in database/i';

    /**
     * After parsing ...
     *
     * Fix address, nameserver and dnssec in WHOIS output
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        $filteredNameserver = array();
        
        if ($ResultSet->dnssec == 'Active') {
            $ResultSet->dnssec = true;
        } else {
            $ResultSet->dnssec = false;
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
        
        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                if (! is_array($contactObject->address)) {
                    $explodedAddress = explode("\n", $contactObject->address);
                    
                    if (sizeof($explodedAddress) == 6) {
                        $contactObject->organization = trim($explodedAddress[0]);
                        $contactObject->address = trim($explodedAddress[1]);
                        $contactObject->city = trim($explodedAddress[2]);
                        $contactObject->country = trim($explodedAddress[3]);
                    }
                    
                    if (sizeof($explodedAddress) == 7) {
                        $contactObject->name = trim($explodedAddress[0]);
                        $contactObject->email = trim($explodedAddress[1]);
                        $contactObject->organization = trim($explodedAddress[2]);
                        $contactObject->address = trim($explodedAddress[3]);
                        $contactObject->city = trim($explodedAddress[4]);
                        $contactObject->country = trim($explodedAddress[5]);
                    }
                    
                    if (sizeof($explodedAddress) == 8) {
                        $contactObject->name = trim($explodedAddress[1]);
                        $contactObject->email = trim($explodedAddress[2]);
                        $contactObject->organization = trim($explodedAddress[3]);
                        $contactObject->address = trim($explodedAddress[4]);
                        $contactObject->city = trim($explodedAddress[5]);
                        $contactObject->country = trim($explodedAddress[6]);
                    }
                    
                    $explodedAddress = array();
                }
            }
        }
    }
}