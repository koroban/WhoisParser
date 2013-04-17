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
 * Template for .TR
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Tr extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(
            1 => '/registrant:\n(.*?)(?=\*\* (administrative contact|registrar))/is', 
            2 => '/administrative contact:\n(.*?)(?=technical contact)/is', 
            3 => '/technical contact:\n(.*?)(?=billing contact)/is', 
            4 => '/billing contact:\n(.*?)(?=domain servers)/is', 
            5 => '/domain servers:\n(.*?)(?=\*\* additional info)/is', 
            6 => '/additional info:\n(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(1 => array('/registrant:\n(.+)$/is' => 'contacts:owner:address'), 
            2 => array('/nic handle(?>[\x20\t]*): (.+)$/im' => 'contacts:admin:handle', 
                    '/organization name(?>[\x20\t]*): (.*)$/im' => 'contacts:admin:organization', 
                    '/address(?>[\x20\t]*): (.+)(?=phone)/is' => 'contacts:admin:address', 
                    '/phone(?>[\x20\t]*): (.+)$/im' => 'contacts:admin:phone', 
                    '/fax(?>[\x20\t]*): (.+)$/im' => 'contacts:admin:fax'), 
            3 => array('/nic handle(?>[\x20\t]*): (.+)$/im' => 'contacts:tech:handle', 
                    '/organization name(?>[\x20\t]*): (.*)$/im' => 'contacts:tech:organization', 
                    '/address(?>[\x20\t]*): (.+)(?=phone)/is' => 'contacts:tech:address', 
                    '/phone(?>[\x20\t]*): (.+)$/im' => 'contacts:tech:phone', 
                    '/fax(?>[\x20\t]*): (.+)$/im' => 'contacts:tech:fax'), 
            4 => array('/nic handle(?>[\x20\t]*): (.+)$/im' => 'contacts:billing:handle', 
                    '/organization name(?>[\x20\t]*): (.*)$/im' => 'contacts:billing:organization', 
                    '/address(?>[\x20\t]*): (.+)(?=phone)/is' => 'contacts:billing:address', 
                    '/phone(?>[\x20\t]*): (.+)$/im' => 'contacts:billing:phone', 
                    '/fax(?>[\x20\t]*): (.+)$/im' => 'contacts:billing:fax'), 
            5 => array('/\n(?>[\x20\t]*)(.+)$/im' => 'nameserver'), 
            6 => array('/created on(?>[\.]*): (.+)$/im' => 'created', 
                    '/expires on(?>[\.]*): (.+)$/im' => 'expires'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No match found for/i';

    /**
     * After parsing do something
     * 
     * Fix contact addresses
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                $contactObject->address = array_map('utf8_encode', explode("\n", trim($contactObject->address)));
                $contactObject->address = array_map('trim', $contactObject->address);
                
                if ($contactType === 'owner') {
                    $contactObject->organization = $contactObject->address[0];
                    $contactObject->phone = $contactObject->address[6];
                    $contactObject->fax = $contactObject->address[7];
                    $contactObject->country = $contactObject->address[4];
                    $contactObject->city = $contactObject->address[2];
                    $contactObject->email = $contactObject->address[5];
                    $contactObject->address = $contactObject->address[1];
                } else {
                    $contactObject->organization = utf8_encode($contactObject->organization);
                    
                    if (sizeof($contactObject->address) === 4) {
                        $contactObject->country = $contactObject->address[3];
                        $contactObject->city = $contactObject->address[2];
                    }
                    
                    $contactObject->address = $contactObject->address[0];
                }
            }
        }
    }
}