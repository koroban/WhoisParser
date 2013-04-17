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
 * Template for IANA #1443
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Gtld_vautron extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Owner Contact:(.*?)(?=Punycode Name)/is', 
            2 => '/Admin Contact(.*?)(?=Technical Contact)/is', 
            3 => '/Technical Contact(.*?)(?=Zone Contact)/is', 
            4 => '/Zone Contact(.*?)(?=Record expires on)/is', 
            5 => '/Record expires on:(.*?)(?=Domain servers in listed order;)/im', 
            6 => '/Domain servers in listed order:[\n]{2}(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/Owner Contact:\n(.*?)$/is' => 'contacts:owner:address'), 
            2 => array('/Admin Contact\n(.*?)$/is' => 'contacts:admin:address'), 
            3 => array('/Technical Contact\n(.*?)$/is' => 'contacts:tech:address'), 
            4 => array('/Zone Contact\n(.*?)$/is' => 'contacts:zone:address'), 
            5 => array('/Record expires on:(.*?)$/is' => 'expires'), 
            6 => array('/[^Domain servers in listed order] .* (.*)$/im' => 'ips'));

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
        
        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                $contactObject->address = $filteredAddress = explode("\n", trim($contactObject->address));
                $contactObject->name = trim($filteredAddress[0]);
                
                if (stripos(end($filteredAddress), 'phone:')) {
                    preg_match('/phone:(.*?)$/im', end($filteredAddress), $matches);
                    
                    if (isset($matches[1])) {
                        $contactObject->phone = trim($matches[1]);
                    }
                } elseif ($contactType !== 'owner') {
                    $contactObject->phone = trim(end($filteredAddress));
                }
                
                if (sizeof($filteredAddress) === 4) {
                    $contactObject->organization = trim($filteredAddress[1]);
                    $contactObject->address = trim($filteredAddress[2]);
                    
                    $matches = explode(',', trim($filteredAddress[3]));
                    $contactObject->city = trim($matches[0]);
                    $contactObject->zipcode = trim($matches[1]);
                    $contactObject->country = trim($matches[2]);
                } else {
                    $contactObject->organization = trim($filteredAddress[1]);
                    $contactObject->email = trim($filteredAddress[2]);
                    $contactObject->address = trim($filteredAddress[3]);
                    
                    $matches = explode(',', trim($filteredAddress[4]));
                    $contactObject->city = trim($matches[0]);
                    $contactObject->zipcode = trim($matches[1]);
                    $contactObject->country = trim($matches[2]);
                }
            }
        }
    }
}