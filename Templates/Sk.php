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
 * Template for .SK
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Sk extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Admin-id(.*?)(?=Tech-id)/is', 
            2 => '/Tech-id(.*?)(?=dns_name)/is', 3 => '/dns_name(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^Admin-id(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:handle', 
                    '/^Admin-name(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/^Admin-address(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:address', 
                    '/^Admin-telephone(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone', 
                    '/^Admin-email(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:email', 
                    '/^Admin-org.-ID(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:orgid'), 
            
            2 => array('/^Tech-id(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:handle', 
                    '/^Tech-name(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/^Tech-address(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:address', 
                    '/^Tech-telephone(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/^Tech-email(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email', 
                    '/^Tech-org.-ID(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:orgid'), 
            
            3 => array('/^dns_name(?>[\x20\t]*)(.+)$/im' => 'nameserver', 
                    '/^dns_IPv4(?>[\x20\t]*)(.+)$/im' => 'ips', 
                    '/^Last-update(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/^Valid-date(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/^Domain-status(?>[\x20\t]*)(.+)$/im' => 'status'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/Not found./i';

    /**
     * After parsing ...
     *
     * Fix telephone number if there are more than one
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                if (strpos($contactObject->phone, ',')) {
                    $contactObject->phone = array_map(trim, explode(',', $contactObject->phone));
                }
            }
        }
    }
}