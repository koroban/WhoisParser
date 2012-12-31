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
 * Template for .IM
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Im extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(
            1 => '/Domain Managers(?>[\x20\t]*)(.*?)(?=Domain Owners \/ Registrant)/is', 
            2 => '/Domain Owners \/ Registrant(?>[\x20\t]*)(.*?)(?=Administrative Contact)/is', 
            3 => '/Administrative Contact(?>[\x20\t]*)(.*?)(?=Billing Contact)/is', 
            4 => '/Billing Contact(?>[\x20\t]*)(.*?)(?=Technical Contact)/is', 
            5 => '/Technical Contact(?>[\x20\t]*)(.*?)(?=Domain Details)/is', 
            6 => '/Domain Details(?>[\x20\t]*)(.*?)(?=Name Server)/is', 
            7 => '/Name Server:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(1 => array('/Name:(?>[\x20\t]*)(.+)$/im' => 'registrar:name'), 
            2 => array('/Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/Address[\n](?>[\x20\t]*)(.+)$/is' => 'contacts:owner:address'), 
            3 => array('/Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/Address[\n](?>[\x20\t]*)(.+)$/is' => 'contacts:admin:address'), 
            4 => array('/Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:name', 
                    '/Address[\n](?>[\x20\t]*)(.+)$/is' => 'contacts:billing:address'), 
            5 => array('/Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/Address[\n](?>[\x20\t]*)(.+)$/is' => 'contacts:tech:address'), 
            6 => array('/Expiry Date:(?>[\x20\t]*)(.+)$/im' => 'expires'), 
            7 => array('/Name Server:(?>[\x20\t]*)(.+)\./im' => 'nameserver'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/was not found/i';

    /**
     * After parsing ...
     *
     * Fix address in WHOIS output
     *
     * @param  object $whoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                if (! is_array($contactObject->address)) {
                    $explodedAddress = explode("\n", $contactObject->address);
                    $contactObject->address = $explodedAddress;
                    
                    if (sizeof($explodedAddress) == 4) {
                        $contactObject->address = trim($explodedAddress[0]);
                        $contactObject->zipcode = trim($explodedAddress[1]);
                        $contactObject->country = trim($explodedAddress[2]);
                    }
                    
                    if (sizeof($explodedAddress) == 5) {
                        $contactObject->address = trim($explodedAddress[0]);
                        $contactObject->city = trim($explodedAddress[1]);
                        $contactObject->zipcode = trim($explodedAddress[2]);
                        $contactObject->country = trim($explodedAddress[3]);
                    }
                    
                    if (sizeof($explodedAddress) == 6) {
                        $contactObject->address = trim($explodedAddress[0]);
                        $contactObject->city = trim($explodedAddress[1]);
                        $contactObject->state = trim($explodedAddress[2]);
                        $contactObject->zipcode = trim($explodedAddress[3]);
                        $contactObject->country = trim($explodedAddress[4]);
                    }
                    
                    if (sizeof($explodedAddress) == 7) {
                        $contactObject->address = array(trim($explodedAddress[0]), 
                                trim($explodedAddress[1]));
                        $contactObject->city = trim($explodedAddress[2]);
                        $contactObject->state = trim($explodedAddress[3]);
                        $contactObject->zipcode = trim($explodedAddress[4]);
                        $contactObject->country = trim($explodedAddress[5]);
                    }
                    
                    $explodedAddress = array();
                }
            }
        }
    }
}