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
 * Template for IANA #13
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Gtld_melbourneit extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(
            1 => '/Domain Name(?>[\.]*)(?>[\x20\t]*)(.*?)(?=Organization Contact Id|Administrative Contact Id|Admin Name)/is', 
            2 => '/(?>[\x20\t]*)(Administrative Contact Id|Admin Name)(?>[\.]*)(?>[\x20\t]*)(.*?)(?=Technical Contact Id|Tech Name)/is', 
            3 => '/(?>[\x20\t]*)(Technical Contact Id|Tech Name)(?>[\.]*)(?>[\x20\t]*)(.*?)$/is', 
            4 => '/(?>[\x20\t]*)Organization Contact Id(?>[\.]*)(?>[\x20\t]*)(.*?)(?=Administrative Contact Id|Admin Name)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^(?>[\x20\t]*)Creation Date(?>[\.]*)(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/^(?>[\x20\t]*)Expiry Date(?>[\.]*)(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/^(?>[\x20\t]*)Organisation Name(?>[\.]*)(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/^(?>[\x20\t]*)Organisation Address(?>[\.]*)(?>[\x20\t]*)(.*)$/im' => 'contacts:owner:address'), 
            2 => array(
                    '/^(?>[\x20\t]*)(Admin|Administrative) Name(?>[\.]*)(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/^(?>[\x20\t]*)Admin Address(?>[\.]*)(?>[\x20\t]*)(.*)$/im' => 'contacts:admin:address', 
                    '/^(?>[\x20\t]*)(Admin|Administrative) Contact Id(?>[\.]*)(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:handle', 
                    '/^(?>[\x20\t]*)(Admin|Administrative) Org(?>[\.]*)(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:organization', 
                    '/^(?>[\x20\t]*)(Admin|Administrative) Street(?>[\.]*)(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:address', 
                    '/^(?>[\x20\t]*)(Admin|Administrative) City(?>[\.]*)(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:city', 
                    '/^(?>[\x20\t]*)(Admin|Administrative) State(?>[\.]*)(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:state', 
                    '/^(?>[\x20\t]*)(Admin|Administrative) PC(?>[\.]*)(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:zipcode', 
                    '/^(?>[\x20\t]*)(Admin|Administrative) (Email|e-mail)(?>[\.]*)(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:email', 
                    '/^(?>[\x20\t]*)(Admin|Administrative) Phone(?>[\.]*)(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone', 
                    '/^(?>[\x20\t]*)(Admin|Administrative) Fax(?>[\.]*)(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:fax'), 
            3 => array(
                    '/^(?>[\x20\t]*)(Tech|Technical) Name(?>[\.]*)(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/^(?>[\x20\t]*)Tech Address(?>[\.]*)(?>[\x20\t]*)(.*)$/im' => 'contacts:tech:address', 
                    '/^(?>[\x20\t]*)(Tech|Technical) Contact Id(?>[\.]*)(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:handle', 
                    '/^(?>[\x20\t]*)(Tech|Technical) Org(?>[\.]*)(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:organization', 
                    '/^(?>[\x20\t]*)(Tech|Technical) Street(?>[\.]*)(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:address', 
                    '/^(?>[\x20\t]*)(Tech|Technical) City(?>[\.]*)(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:city', 
                    '/^(?>[\x20\t]*)(Tech|Technical) State(?>[\.]*)(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:state', 
                    '/^(?>[\x20\t]*)(Tech|Technical) PC(?>[\.]*)(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:zipcode', 
                    '/^(?>[\x20\t]*)(Tech|Technical) (Email|e-mail)(?>[\.]*)(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email', 
                    '/^(?>[\x20\t]*)(Tech|Technical) Phone(?>[\.]*)(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/^(?>[\x20\t]*)(Tech|Technical) Fax(?>[\.]*)(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:fax', 
                    '/^(?>[\x20\t]*)Name Server(?>[\.]*)(?>[\x20\t]*)(.+)$/im' => 'nameserver'), 
            4 => array(
                    '/^(?>[\x20\t]*)Organization Name(?>[\.]*)(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/^(?>[\x20\t]*)Organization Address(?>[\.]*)(?>[\x20\t]*)(.*)$/im' => 'contacts:owner:address', 
                    '/^(?>[\x20\t]*)Organization Contact Id(?>[\.]*)(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:handle', 
                    '/^(?>[\x20\t]*)Organization Org(?>[\.]*)(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization', 
                    '/^(?>[\x20\t]*)Organization Street(?>[\.]*)(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address', 
                    '/^(?>[\x20\t]*)Organization City(?>[\.]*)(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:city', 
                    '/^(?>[\x20\t]*)Organization State(?>[\.]*)(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:state', 
                    '/^(?>[\x20\t]*)Organization PC(?>[\.]*)(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:zipcode', 
                    '/^(?>[\x20\t]*)Organization (Email|e-mail)(?>[\.]*)(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:email', 
                    '/^(?>[\x20\t]*)Organization Phone(?>[\.]*)(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:phone', 
                    '/^(?>[\x20\t]*)Organization Fax(?>[\.]*)(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:fax'));

    /**
     * After parsing do something
     *
     * Fix address
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                if (is_array($contactObject->address)) {
                    if (isset($contactObject->address[2])) {
                        $contactObject->city = $contactObject->address[2];
                    }
                    if (isset($contactObject->address[3])) {
                        $contactObject->zipcode = $contactObject->address[3];
                    }
                    if (isset($contactObject->address[4])) {
                        $contactObject->state = $contactObject->address[4];
                    }
                    if (isset($contactObject->address[5])) {
                        $contactObject->country = $contactObject->address[5];
                    }
                    if ($contactObject->address[1] != '') {
                        $contactObject->address = array($contactObject->address[0], 
                                $contactObject->address[1]);
                    } else {
                        $contactObject->address = $contactObject->address[0];
                    }
                }
            }
        }
    }
}