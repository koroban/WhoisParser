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
 * Template for .CA
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
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
    protected $blocks = array(1 => '/domain name:(?>[\x20\t]*)(.*?)(?=registrar)/is', 
            2 => '/registrar:(?>[\x20\t]*)(.*?)(?=registrant|name servers)/is', 
            3 => '/registrant:(?>[\x20\t]*)(.*?)(?=administrative contact)/is', 
            4 => '/administrative contact:(?>[\x20\t]*)(.*?)(?=technical contact)/is', 
            5 => '/technical contact:(?>[\x20\t]*)(.*?)(?=name servers)/is', 
            6 => '/name servers:(?>[\x20\t]*)(.*?)(?=% whois)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/domain status:(?>[\x20\t]*)(.+)$/im' => 'status', 
                    '/creation Date:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/expiry Date:(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/updated date:(?>[\x20\t]*)(.+)$/im' => 'changed'), 
            2 => array('/name:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/number:(?>[\x20\t]*)(.*)$/im' => 'registrar:id'), 
            3 => array('/name:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name'), 
            4 => array('/name:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/postal address:(?>[\x20\t]*)(.+)(?=Phone)/is' => 'contacts:admin:address', 
                    '/email:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:email', 
                    '/phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone', 
                    '/fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:fax'), 
            5 => array('/name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/postal address:(?>[\x20\t]*)(.+)(?=Phone)/is' => 'contacts:tech:address', 
                    '/email:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email', 
                    '/phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:fax'), 
            6 => array('/\n(?>[\x20\t]+)(.+)$/im' => 'nameserver'));

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
     * Fix addresses
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                if ($contactObject->address != '') {
                    $contactObject->address = array_map('trim', explode("\n", trim($contactObject->address)));
                }
            }
        }
    }
}