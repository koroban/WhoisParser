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
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * @namespace Novutec\WhoisParser
 */
namespace Novutec\WhoisParser;

/**
 * Template for .RS
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Rs extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/(?>[\x20\t]*)Domain name:(?>[\x20\t]*)(.*?)(?=Owner:)/is', 
            2 => '/(?>[\x20\t]*)Domain name:(?>[\x20\t]*)(.*?)(?=DNS:)/is', 
            3 => '/(?>[\x20\t]*)DNS:(?>[\x20\t]*)(.*?)(?=Administrative contact)/is', 
            4 => '/(?>[\x20\t]*)Administrative contact:(?>[\x20\t]*)(.*?)(?=Technical contact)/is', 
            5 => '/(?>[\x20\t]*)Technical contact:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^(?>[\x20\t]*)Domain status:(?>[\x20\t]*)(.+)$/im' => 'status', 
                    '/^(?>[\x20\t]*)Registration date:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/^(?>[\x20\t]*)Modification date:(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/^(?>[\x20\t]*)Expiration date:(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/^(?>[\x20\t]*)Registrar:(?>[\x20\t]*)(.+)$/im' => 'registrar:name'), 
            
            2 => array('/^(?>[\x20\t]*)Owner:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/^(?>[\x20\t]*)Address:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address'), 
            
            3 => array('/^(?>[\x20\t]*)DNS:(?>[\x20\t]*)(.+)\. - .*$/im' => 'nameserver', 
                    '/^(?>[\x20\t]*)DNS:(?>[\x20\t]*).+\. - (.*)$/im' => 'ips'), 
            
            4 => array(
                    '/^(?>[\x20\t]*)Administrative contact:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/^(?>[\x20\t]*)Address:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:address'), 
            
            5 => array(
                    '/^(?>[\x20\t]*)Technical contact:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/^(?>[\x20\t]*)Address:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:address'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/Domain is not registered/i';

    /**
     * After parsing ...
     *
     * Fix address, registrar handle and nameserver in whois output
     *
     * @param  object $WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                $explodedAddress = explode(',', trim($contactObject->address));
                
                if (sizeof($explodedAddress) == 3) {
                    $contactObject->address = trim($explodedAddress[0]);
                    $contactObject->city = trim($explodedAddress[1]);
                    $contactObject->country = trim($explodedAddress[2]);
                }
                
                $explodedName = explode(',', trim($contactObject->name));
                
                if (sizeof($explodedName) == 2) {
                    $contactObject->name = trim($explodedName[0]);
                    $contactObject->organization = trim($explodedName[1]);
                }
            }
        }
    }
}