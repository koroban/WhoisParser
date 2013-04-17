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
 * Template for .SM
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Sm extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/domain name:(?>[\x20\t]*)(.*?)(?=owner)/is', 
            2 => '/owner:\n(?>[\x20\t]*)(.*?)(?=technical contact)/is', 
            3 => '/technical contact:\n(?>[\x20\t]*)(.*?)(?=dns servers)/is', 
            4 => '/dns servers:\n(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/registration date:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/last update:(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/status:(?>[\x20\t]*)(.+)$/im' => 'status'), 
            2 => array('/owner:\n(?>[\x20\t]*)(.+)(?=phone)/is' => 'contacts:owner:address', 
                    '/phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:phone', 
                    '/fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:fax', 
                    '/email:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:email'), 
            3 => array(
                    '/technical contact:\n(?>[\x20\t]*)(.+)(?=phone)/is' => 'contacts:tech:address', 
                    '/phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:fax', 
                    '/email:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email'), 
            4 => array('/\n(?>[\x20\t]*)(.+)$/im' => 'nameserver'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No entries found./i';

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
                $filteredAddress = array_map('trim', explode("\n", trim($contactObject->address)));
                
                $contactObject->name = $filteredAddress[0];
                $contactObject->organization = $filteredAddress[1];
                $contactObject->address = $filteredAddress[2];
                $contactObject->city = $filteredAddress[3];
                $contactObject->country = $filteredAddress[4];
            }
        }
    }
}