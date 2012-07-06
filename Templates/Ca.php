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
 * Template for .CA
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Ca extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Domain name:(?>[\x20\t]*)(.*?)(?=Registrar)/is', 
            2 => '/(?>[\x20\t]*)Registrar:(?>[\x20\t]*)(.*?)(?=Registrant:|Name servers:)/is', 
            3 => '/(?>[\x20\t]*)Registrant:(?>[\x20\t]*)(.*?)(?=Administrative contact)/is', 
            4 => '/(?>[\x20\t]*)Administrative contact:(?>[\x20\t]*)(.*?)(?=Technical contact)/is', 
            5 => '/(?>[\x20\t]*)Technical contact:(?>[\x20\t]*)(.*?)(?=Name servers)/is', 
            6 => '/(?>[\x20\t]*)Name servers:(?>[\x20\t]*)(.*?)[\r\n]{2}/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^(?>[\x20\t]*)Domain status:(?>[\x20\t]*)(.+)$/im' => 'status', 
                    '/^(?>[\x20\t]*)Creation Date:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/^(?>[\x20\t]*)Expiry Date:(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/^(?>[\x20\t]*)Updated date:(?>[\x20\t]*)(.+)$/im' => 'changed'), 
            2 => array('/^(?>[\x20\t]*)Name:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/^(?>[\x20\t]*)Number:(?>[\x20\t]*)(.*)$/im' => 'registrar:id'), 
            3 => array('/^(?>[\x20\t]*)Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name'), 
            4 => array('/^(?>[\x20\t]*)Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/(?>[\x20\t]*)Postal address:(?>[\x20\t]*)(.+)(?=Phone)/is' => 'contacts:admin:address', 
                    '/^(?>[\x20\t]*)Email:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:email', 
                    '/^(?>[\x20\t]*)Phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone', 
                    '/^(?>[\x20\t]*)Fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:fax'), 
            5 => array('/^(?>[\x20\t]*)Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/(?>[\x20\t]*)Postal address:(?>[\x20\t]*)(.+)(?=Phone)/is' => 'contacts:tech:address', 
                    '/^(?>[\x20\t]*)Email:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email', 
                    '/^(?>[\x20\t]*)Phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/^(?>[\x20\t]*)Fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:fax'), 
            6 => array('/(?>[\x20\t]*)Name Servers:(?>[\x20\t]*)(.*?)[\r\n]{2}/is' => 'nameserver'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/Domain status:(?>[\x20\t]*)available/i';

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
        $filteredAddress = array();
        $filteredNameserver = array();
        
        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                if (! is_array($contactObject->address)) {
                    $explodedAddress = explode("\n", $contactObject->address);
                    
                    foreach ($explodedAddress as $key => $line) {
                        if (trim($line) != '') {
                            $filteredAddress[] = trim($line);
                        }
                    }
                    
                    $contactObject->address = $filteredAddress;
                    $filteredAddress = array();
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