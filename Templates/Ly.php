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
 * Template for .LY
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Ly extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Registrant:\n(.*?)(?=Domain Name)/is', 
            2 => '/Administrative Contact:\n(.*?)(?=Technical Contact)/is', 
            3 => '/Technical Contact:\n(.*?)(?=Billing Contact|Created:)/is', 
            4 => '/Billing Contact:\n(.*?)(?=Created)/is', 
            5 => '/Created:(.*?)(?=Domain servers in listed order)/is', 
            6 => '/Domain servers in listed order:\n(?>[\x20\t]*)(.*?)\n\n/is', 
            7 => '/Domain Status:(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/Registrant:\n(.*)$/is' => 'contacts:owner:address', 
                    '/Zip\/Postal code: (.+)$/im' => 'contacts:owner:zipcode', 
                    '/Phone: (.+)$/im' => 'contacts:owner:phone', 
                    '/Fax: (.+)$/im' => 'contacts:owner:fax'), 
            2 => array('/Administrative Contact:\n(.*)$/is' => 'contacts:admin:address', 
                    '/Zip\/Postal code: (.+)$/im' => 'contacts:admin:zipcode', 
                    '/Phone: (.+)$/im' => 'contacts:admin:phone', 
                    '/Fax: (.+)$/im' => 'contacts:admin:fax'), 
            3 => array('/Technical Contact:\n(.*)$/is' => 'contacts:tech:address', 
                    '/Zip\/Postal code: (.+)$/im' => 'contacts:tech:zipcode', 
                    '/Phone: (.+)$/im' => 'contacts:tech:phone', 
                    '/Fax: (.+)$/im' => 'contacts:tech:fax'), 
            4 => array('/Billing Contact:\n(.*)$/is' => 'contacts:billing:address', 
                    '/Zip\/Postal code: (.+)$/im' => 'contacts:billing:zipcode', 
                    '/Phone: (.+)$/im' => 'contacts:billing:phone', 
                    '/Fax: (.+)$/im' => 'contacts:billing:fax'), 
            5 => array('/Created:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/Updated:(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/Expired:(?>[\x20\t]*)(.+)$/im' => 'expires'), 
            6 => array('/\n(?>[\x20\t]*)(.+)$/im' => 'nameserver'), 
            7 => array('/Domain Status:(?>[\x20\t]*)(.+)$/im' => 'status'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/Not found/i';

    /**
     * After parsing ...
     * 
     * Fix contact addresses
     * 
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        $filteredAddress = array();
        
        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                $filteredAddress = array_map('trim', explode("\n", trim($contactObject->address)));
                
                $contactObject->organization = $filteredAddress[0];
                $contactObject->name = $filteredAddress[1];
                $contactObject->address = $filteredAddress[2];
                $contactObject->city = $filteredAddress[3];
                
                if (stripos($filteredAddress[5], 'Zip/Postal code') !== false) {
                    $contactObject->country = $filteredAddress[4];
                } else {
                    $contactObject->state = $filteredAddress[4];
                    $contactObject->country = $filteredAddress[5];
                }
                
                $contactObject->email = end($filteredAddress);
            }
        }
    }
}