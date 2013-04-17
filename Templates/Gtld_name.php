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
 * Template for IANA #625
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Gtld_name extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(
            1 => '/registrant contact info(.*?)(?=administrative contact info)/is', 
            2 => '/administrative contact info(.*?)(?=technical contact info)/is', 
            3 => '/technical contact info(.*?)(?=billing contact info)/is', 
            4 => '/billing contact info(.*?)(?=Timestamp:)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array(
                    '/registrant contact info\n(?>[\x20\t]*)(.+)(?=Phone)/is' => 'contacts:owner:address', 
                    '/Phone:(?>[\x20\t]*)(.+)/im' => 'contacts:owner:phone', 
                    '/Fax:(?>[\x20\t]*)(.+)/im' => 'contacts:owner:fax', 
                    '/Email Address:(?>[\x20\t]*)(.+)/im' => 'contacts:owner:email'), 
            2 => array(
                    '/administrative contact info\n(?>[\x20\t]*)(.+)(?=Phone)/is' => 'contacts:admin:address', 
                    '/Phone:(?>[\x20\t]*)(.+)/im' => 'contacts:admin:phone', 
                    '/Fax:(?>[\x20\t]*)(.+)/im' => 'contacts:admin:fax', 
                    '/Email Address:(?>[\x20\t]*)(.+)/im' => 'contacts:admin:email'), 
            3 => array(
                    '/technical contact info\n(?>[\x20\t]*)(.+)(?=Phone)/is' => 'contacts:tech:address', 
                    '/Phone:(?>[\x20\t]*)(.+)/im' => 'contacts:tech:phone', 
                    '/Fax:(?>[\x20\t]*)(.+)/im' => 'contacts:tech:fax', 
                    '/Email Address:(?>[\x20\t]*)(.+)/im' => 'contacts:tech:email'), 
            4 => array(
                    '/billing contact info\n(?>[\x20\t]*)(.+)(?=Phone)/is' => 'contacts:billing:address', 
                    '/Phone:(?>[\x20\t]*)(.+)/im' => 'contacts:billing:phone', 
                    '/Fax:(?>[\x20\t]*)(.+)/im' => 'contacts:billing:fax', 
                    '/Email Address:(?>[\x20\t]*)(.+)/im' => 'contacts:billing:email'));

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
                
                if (sizeof($filteredAddress) === 7) {
                    $contactObject->organization = $filteredAddress[0];
                    $contactObject->name = $filteredAddress[1];
                    $contactObject->address = $filteredAddress[2];
                    $contactObject->city = $filteredAddress[3];
                    $contactObject->state = $filteredAddress[4];
                    $contactObject->zipcode = $filteredAddress[5];
                    $contactObject->country = $filteredAddress[6];
                }
            }
        }
    }
}