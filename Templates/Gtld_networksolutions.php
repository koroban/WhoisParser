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
 * Template for Gtld_networsolutions
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Gtld_networksolutions extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Registrant:(.*?)(?=Domain Name:)/is', 
            2 => '/Administrative Contact(:|, Technical Contact:)(.*?)(?=Record expires on|Technical Contact)/is', 
            3 => '/Technical Contact:(.*?)(?=Record expires on)/is', 
            4 => '/Database last updated on (.*?)$/im', 
            5 => '/Domain servers in listed order:[\n]{2}(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(1 => array('/Registrant:\n(.*?)$/is' => 'contacts:owner:address'), 
            2 => array(
                    '/Administrative Contact, Technical Contact:\n(.*?)$/is' => 'contacts:admin:address'), 
            3 => array('/Technical Contact:\n(.*?)$/is' => 'contacts:tech:address'), 
            4 => array('/Database last updated on (.*?)$/is' => 'changed'), 
            5 => array('/[^Domain servers in listed order] .* (.*)$/im' => 'ips'));

    /**
     * After parsing do something
     *
     * Fix address
     *
     * @param  object $whoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                $filteredAddress = explode("\n", $contactObject->address);
                $contactObject->address = $filteredAddress;
                
                preg_match('/([a-z0-9\.\-, ]*)(?>[\x20\t]*)(.*)$/i', $filteredAddress[0], $matches);
                
                if (isset($matches[1])) {
                    $contactObject->name = trim($matches[1]);
                }
                
                if (isset($matches[2])) {
                    $contactObject->email = trim($matches[2]);
                }
                
                preg_match('/([0-9\-\+\.\/]*) fax: ([0-9\-\+\.\/]*)/i', $filteredAddress[5], $matches);
                
                if (isset($matches[1])) {
                    $contactObject->phone = trim($matches[1]);
                }
                
                if (isset($matches[2])) {
                    $contactObject->fax = trim($matches[2]);
                }
                
                $contactObject->organization = trim($filteredAddress[1]);
                $contactObject->address = trim($filteredAddress[2]);
                $contactObject->city = trim($filteredAddress[3]);
                $contactObject->country = trim($filteredAddress[4]);
            }
        }
    }
}