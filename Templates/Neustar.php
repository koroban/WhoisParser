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
 * Template for Neustar
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Neustar extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Domain Name:(?>[\x20\t]*)(.*?)(?=Registrant ID\:)/is', 
            2 => '/Registrant ID:(?>[\x20\t]*)(.*?)(?=Administrative Contact ID\:)/is', 
            3 => '/Administrative Contact ID:(?>[\x20\t]*)(.*?)(?=Billing Contact ID\:)/is', 
            4 => '/Billing Contact ID:(?>[\x20\t]*)(.*?)(?=Technical Contact ID\:)/is', 
            5 => '/Technical Contact ID:(?>[\x20\t]*)(.*?)(?=Name Server\:)/is', 
            6 => '/Name Server:(?>[\x20\t]*)(.*?)(?=Created by Registrar\:)/is', 
            7 => '/Domain Registration Date:(?>[\x20\t]*)(.*?)(?=>>>>)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^Sponsoring Registrar:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/^Sponsoring Registrar IANA ID:(?>[\x20\t]*)(.+)$/im' => 'registrar:id', 
                    '/^Registrar URL \(registration services\):(?>[\x20\t]*)(.+)$/im' => 'registrar:url', 
                    '/^(?>Domain )*Status:(?>[\x20\t]*)(.+)$/im' => 'status'), 
            
            2 => array('/^Registrant ID:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:handle', 
                    '/^Registrant Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/^Registrant Organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization', 
                    '/^Registrant Address[0-9]*:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address', 
                    '/^Registrant City:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:city', 
                    '/^Registrant State\/Province:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:state', 
                    '/^Registrant Postal Code:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:zipcode', 
                    '/^Registrant Country Code:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:country', 
                    '/^Registrant Phone Number:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:phone', 
                    '/^Registrant Facsimile Number:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:fax', 
                    '/^Registrant Email:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:email', 
                    '/^Registrant Application Purpose:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:application_purpose', 
                    '/^Registrant Nexus Category:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:nexus_category'), 
            3 => array(
                    '/^Administrative Contact ID:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:handle', 
                    '/^Administrative Contact Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/^Administrative Contact Organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:organization', 
                    '/^Administrative Contact Address[0-9]*:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:address', 
                    '/^Administrative Contact City:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:city', 
                    '/^Administrative Contact State\/Province:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:state', 
                    '/^Administrative Contact Postal Code:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:zipcode', 
                    '/^Administrative Contact Country Code:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:country', 
                    '/^Administrative Contact Phone Number:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone', 
                    '/^Administrative Contact Facsimile Number:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:fax', 
                    '/^Administrative Contact Email:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:email', 
                    '/^Administrative Application Purpose:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:application_purpose', 
                    '/^Administrative Nexus Category:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:nexus_category'), 
            4 => array('/^Billing Contact ID:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:handle', 
                    '/^Billing Contact Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:name', 
                    '/^Billing Contact Organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:organization', 
                    '/^Billing Contact Address[0-9]*:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:address', 
                    '/^Billing Contact City:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:city', 
                    '/^Billing Contact State\/Province:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:state', 
                    '/^Billing Contact Postal Code:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:zipcode', 
                    '/^Billing Contact Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:country', 
                    '/^Billing Contact Phone Number:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:phone', 
                    '/^Billing Contact Facsimile Number:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:fax', 
                    '/^Billing Contact Email:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:email', 
                    '/^Billing Application Purpose:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:application_purpose', 
                    '/^Billing Nexus Category:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:nexus_category'), 
            5 => array('/^Technical Contact ID:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:handle', 
                    '/^Technical Contact Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/^Technical Contact Organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:organization', 
                    '/^Technical Contact (Street|Address)[0-9]*:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:address', 
                    '/^Technical Contact City:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:city', 
                    '/^Technical Contact State\/Province:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:state', 
                    '/^Technical Contact Postal Code:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:zipcode', 
                    '/^Technical Contact Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:country', 
                    '/^Technical Contact Phone Number:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/^Technical Contact Facsimile Number:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:fax', 
                    '/^Technical Contact Email:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email', 
                    '/^Technical Application Purpose:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:application_purpose', 
                    '/^Technical Nexus Category:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:nexus_category'), 
            6 => array('/^Name Server:(?>[\x20\t]*)(.+)$/im' => 'nameserver'), 
            7 => array('/^Domain Registration Date:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/^Domain Expiration Date:(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/^Domain Last Updated Date:(?>[\x20\t]*)(.+)$/im' => 'changed'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/Not found:/i';

    /**
     * After parsing do something
     *
     * Clear empty lines at address and nameservers
     *
     * @param  object $whoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        $filteredAddress = array();
        
        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                if (is_array($contactObject->address)) {
                    foreach ($contactObject->address as $key => $line) {
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
                 is_array($ResultSet->nameserver)) {
            foreach ($ResultSet->nameserver as $key => $line) {
                if (trim($line) != '') {
                    $filteredAddress[] = strtolower(trim($line));
                }
            }
            
            $ResultSet->nameserver = $filteredAddress;
            $filteredAddress = array();
        }
    }
}