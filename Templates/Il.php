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
 * Template for .IL
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Il extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/query:(?>[\x20\t]*)(.*?)(?=changed)/is', 
            2 => '/person:(?>[\x20\t]*).*?[\n]{2}/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^descr:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address', 
                    '/^phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:phone', 
                    '/^fax-no:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:fax', 
                    '/^e-mail:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:email', 
                    '/^admin-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:admin', 
                    '/^tech-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:tech', 
                    '/^zone-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:zone', 
                    '/^nserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver', 
                    '/^validity:(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/^status:(?>[\x20\t]*)(.+)$/im' => 'status'), 
            
            2 => array('/^nic-hdl:(?>[\x20\t]*)(.+)$/im' => 'contacts:handle', 
                    '/^person:(?>[\x20\t]*)(.+)$/im' => 'contacts:name', 
                    '/^e-mail:(?>[\x20\t]*)(.+)$/im' => 'contacts:email', 
                    '/^address:(?>[\x20\t]*)(.+)$/im' => 'contacts:address', 
                    '/^phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:phone', 
                    '/^fax-no:(?>[\x20\t]*)(.+)$/im' => 'contacts:fax'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No data was found to match/i';

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
                $contactObject->email = str_replace(' AT ', '@', $contactObject->email);
                
                if (is_array($contactObject->address) && sizeof($contactObject->address) == 5) {
                    if (isset($contactObject->address[0])) {
                        $contactObject->organization = $contactObject->address[0];
                    }
                    if (isset($contactObject->address[4])) {
                        $contactObject->country = $contactObject->address[4];
                    }
                    if (isset($contactObject->address[2])) {
                        $contactObject->city = $contactObject->address[2];
                    }
                    if (isset($contactObject->address[3])) {
                        $contactObject->zipcode = $contactObject->address[3];
                    }
                    if (isset($contactObject->address[1])) {
                        $contactObject->address = $contactObject->address[1];
                    }
                }
            }
        }
    }
}