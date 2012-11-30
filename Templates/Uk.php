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
 * Template for .UK
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Uk extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/(?>[\x20\t]*)Registrant:(.*?)(?=Registrant type:)/is', 
            2 => '/(?>[\x20\t]*)address:(.*?)(?=Registrar:)/is', 
            3 => '/(?>[\x20\t]*)Registrar:(.*?)(?=Relevant dates:)/is', 
            4 => '/(?>[\x20\t]*)Relevant dates:(.*?)(?=Registration status:)/is', 
            5 => '/(?>[\x20\t]*)Registration status:(.*?)(?=Name servers:)/is', 
            6 => '/(?>[\x20\t]*)Name servers:(.*?)(?=WHOIS lookup made)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^(?>[\x20\t]*)Registrant:(?>[\n\x20\t]*)(.+)/im' => 'contacts:owner:name'), 
            2 => array('/^(?>[\x20\t]*)address:(?>[\n\x20\t]*)(.+)$/is' => 'contacts:owner:address'), 
            3 => array('/^(?>[\x20\t]*)Registrar:(?>[\n\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/^(?>[\x20\t]*)Url:(?>[\n\x20\t]*)(.+)$/im' => 'registrar:url', 
                    '/\[Tag = (.+)\]$/im' => 'registrar:id'), 
            4 => array('/^(?>[\x20\t]*)Registered on:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/^(?>[\x20\t]*)Expiry date:(?>[\x20\t]*)(.*)$/im' => 'expires', 
                    '/^(?>[\x20\t]*)Last updated:(?>[\x20\t]*)(.+)$/im' => 'changed'), 
            5 => array('/^(?>[\x20\t]*)Registration status:(?>[\n\x20\t]*)(.+)/im' => 'status'), 
            6 => array('/(?>[\x20\t]*)Name servers:(?>[\n\x20\t]*)(.+)$/is' => 'nameserver'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/This domain name has not been registered./i';

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
        $filteredNameserver = array();
        
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
                $explodedAddress = explode("\n", $contactObject->address);
                
                $contactObject->address = trim($explodedAddress[0]);
                $contactObject->city = trim($explodedAddress[1]);
                $contactObject->state = trim($explodedAddress[2]);
                $contactObject->zipcode = trim($explodedAddress[3]);
                $contactObject->country = trim($explodedAddress[4]);
            }
        }
    }
}