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
 * Template for .JP
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Jp extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/\[(Registrant|Organization)\](?>[\x20\t]*)(.*?)$/im', 
            2 => '/\[Name Server\](?>[\x20\t]*)(.*?)(?=Contact Information:|$)/is', 
            3 => '/Contact Information:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array(
                    '/\[(Registrant|Organization)\](?>[\x20\t]*)(.*?)$/im' => 'contacts:owner:organization'), 
            2 => array('/\[Name Server\](?>[\x20\t]*)(.+)$/im' => 'nameserver', 
                    '/\[Signing Key\](?>[\x20\t]*)(.+)$/im' => 'dnssec', 
                    '/\[(Created on|Registered Date)\](?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/\[Expires on\](?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/\[(Status|state)\](?>[\x20\t]*)(.+)$/im' => 'status', 
                    '/\[Last (Update|Updated)\](?>[\x20\t]*)(.+)$/im' => 'changed'), 
            3 => array('/\[Name\](?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/\[Email\](?>[\x20\t]*)(.+)$/im' => 'contacts:owner:email', 
                    '/\[Postal code\](?>[\x20\t]*)(.+)$/im' => 'contacts:owner:zipcode', 
                    '/\[Postal Address\](?>[\x20\t]*)(.+)(?=\[Phone\])/is' => 'contacts:owner:address', 
                    '/\[Phone\](?>[\x20\t]*)(.+)$/im' => 'contacts:owner:phone', 
                    '/\[Fax\](?>[\x20\t]*)(.+)$/im' => 'contacts:owner:fax'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No match!!/i';

    /**
     * After parsing ...
     *
     * Fix address in WHOIS output
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        if ($ResultSet->dnssec != '') {
            $ResultSet->dnssec = true;
        } else {
            $ResultSet->dnssec = false;
        }
        
        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                if (! is_array($contactObject->address)) {
                    $explodedAddress = explode("\n", $contactObject->address);
                    
                    if (sizeof($explodedAddress) == 4) {
                        $contactObject->city = trim($explodedAddress[0]);
                        $contactObject->address = trim($explodedAddress[1]);
                        $contactObject->country = trim($explodedAddress[2]);
                    } else {
                        $contactObject->address = trim($contactObject->address);
                    }
                    
                    $explodedAddress = array();
                }
            }
        }
    }
}