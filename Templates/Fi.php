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
 * Template for .FI
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Fi extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/domain:(?>[\x20\t]*)(.*?)(?=More information is)/is', 
            2 => '/descr:(?>[\x20\t]*)(.*?)(?=status)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^created:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/^modified:(?>[\x20\t]*)(.+)$/im' => 'modified', 
                    '/^expires:(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/^status:(?>[\x20\t]*)(.+)$/im' => 'status', 
                    '/^dnssec:(?>[\x20\t]*)(.+)$/im' => 'dnssec', 
                    '/^nserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver'), 
            2 => array('/^descr:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization', 
                    '/^address:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address', 
                    '/^phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:phone'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/Domain not found/i';

    /**
     * After parsing ...
     *
     * If dnssec was matched before it we switch dnssec to true otherwise to false
     *
     * @param  object $whoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                if (is_array($contactObject->organization)) {
                    $contactObject->organization = $contactObject->organization[0];
                }
                
                if (is_array($contactObject->address)) {
                    if (isset($contactObject->address[0])) {
                        $contactObject->name = $contactObject->address[0];
                    }
                    if (isset($contactObject->address[3])) {
                        $contactObject->city = $contactObject->address[3];
                    }
                    if (isset($contactObject->address[2])) {
                        $contactObject->zipcode = $contactObject->address[2];
                    }
                    if (isset($contactObject->address[1])) {
                        $contactObject->address = $contactObject->address[1];
                    }
                }
            }
        }
    }
}