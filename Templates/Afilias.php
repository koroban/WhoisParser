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
 * Template for Afilias
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Afilias extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(
            1 => '/Domain (ID|Name)(?>[\x20\t]*):(?>[\x20\t]*)(.*?)(?=Registrant(\-| )ID|Name Server|Registrant (ID|Name)|Owner Organization|$)/is', 
            2 => '/(Registrant|Owner)(\-| )(ID|Name|Organization)(?>[\x20\t]*):(?>[\x20\t]*)(.*?)(?=(Admin(\-| )(ID|Organization|Name)|Administrative (ID|Name|Contact (Name|ID)|Organization)|Name Server))/is', 
            3 => '/(Admin|Administrative)(\-| )(ID|Name|Contact (Name|ID)|Organization)(?>[\x20\t]*):(?>[\x20\t]*)(.*?)(?=(Billing(\-| )(ID|Name)|(Tech|Technical)(\-| )(ID|Name|Contact (Name|ID)|Organization)|Name Server))/is', 
            4 => '/Billing(\-| )(ID|Name|Contact (Name|ID)|Organization)(?>[\x20\t]*):(?>[\x20\t]*)(.*?)(?=(Tech(\-| )(Name|ID|Contact (Name|ID))|Technical ID|CED ID|Name Server|Nameserver))/is', 
            5 => '/(Tech|Technical)(\-| )(ID|Name|Contact (Name|ID)|Organization)(?>[\x20\t]*):(?>[\x20\t]*)(.*?)(?=(Name Server|Nameservers|Nameserver|Billing (Name|ID)))/is', 
            6 => '/(Name Server|Name Server Name|Nameservers)(?>[\x20\t]*):(?>[\x20\t]*)(.*?)$/is', 
            7 => '/CED ID(?>[\x20\t]*):(?>[\x20\t]*)(.*?)(?=Operations and Notifications ID\:)/is', 
            8 => '/(Registration Date|Created On)(?>[\x20\t]*):(?>[\x20\t]*)(.*?)$/is', 
            9 => '/Zone (ID|Name)(?>[\x20\t]*):(?>[\x20\t]*)(.*?)(?=(Name Server\:|Nameservers\:))/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array(
                    '/^(?>Domain )*(Create(d)*|Creation) (On|Date)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/^(?>Domain )*(Last )*Updated (On|Date)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/^(?>Domain )*(Registry )*(Expiration|Expiry|Expires) (On|Date)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/^Sponsoring Registrar(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/^(?>Domain )*Status(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'status', 
                    '/^Whois Server(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'ask_whois', 
                    '/^ENS_AuthId(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'network:aero_ens_auth_id'), 
            
            2 => array(
                    '/^(Registrant|Owner)(\-| )ID(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:handle', 
                    '/^(Registrant|Owner)(\-| )(Contact Name|Name)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/^(Registrant|Owner)( Organization)*(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization', 
                    '/^(Registrant|Owner)(\-| )(Street|Address)[0-9]*(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address', 
                    '/^(Registrant|Owner)(\-| )City(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:city', 
                    '/^(Registrant|Owner)(\-| )State\/Province(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:state', 
                    '/^(Registrant|Owner)(\-| )Postal(\-| )Code(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:zipcode', 
                    '/^(Registrant|Owner)(\-| )ZIP(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:zipcode', 
                    '/^(Registrant|Owner)(\-| )Country(\/Economy)*(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:country', 
                    '/^(Registrant|Owner)(\-| )Phone(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:phone', 
                    '/^(Registrant|Owner)(\-| )FAX(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:fax', 
                    '/^(Registrant|Owner)(\-| )(Contact Email|Email|E-Mail)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:email'), 
            3 => array(
                    '/^(Admin|Administrative)(\-| )(Contact )?ID(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:handle', 
                    '/^(Admin|Administrative)(\-| )(Contact )?Name(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/^(Admin|Administrative)(\-| )(Contact )?Organization(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:organization', 
                    '/^(Admin|Administrative)(\-| )(Contact )?(Street|Address)[0-9]*(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:address', 
                    '/^(Admin|Administrative)(\-| )(Contact )?City(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:city', 
                    '/^(Admin|Administrative)(\-| )(Contact )?State\/Province(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:state', 
                    '/^(Admin|Administrative)(\-| )(Contact )?Postal(\-| )Code(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:zipcode', 
                    '/^(Admin|Administrative)(\-| )(Contact )?ZIP(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:zipcode', 
                    '/^(Admin|Administrative)(\-| )(Contact )?Country(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:country', 
                    '/^(Admin|Administrative)(\-| )(Contact )?Phone(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone', 
                    '/^(Admin|Administrative)(\-| )(Contact )?FAX(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:fax', 
                    '/^(Admin|Administrative)(\-| )(Contact )?(Email|E-Mail)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:email'), 
            4 => array(
                    '/^Billing(\-| )(Contact )?ID(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:handle', 
                    '/^Billing(\-| )(Contact )?Name(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:name', 
                    '/^Billing(\-| )(Contact )?Organization(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:organization', 
                    '/^Billing(\-| )(Contact )?(Street|Address)[0-9]*(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:address', 
                    '/^Billing(\-| )(Contact )?City(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:city', 
                    '/^Billing(\-| )(Contact )?State\/Province(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:state', 
                    '/^Billing(\-| )(Contact )?Postal(\-| )Code(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:zipcode', 
                    '/^Billing(\-| )(Contact )?ZIP(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:zipcode', 
                    '/^Billing(\-| )(Contact )?Country(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:country', 
                    '/^Billing(\-| )(Contact )?Phone(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:phone', 
                    '/^Billing(\-| )(Contact )?FAX(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:fax', 
                    '/^Billing(\-| )(Contact )?(Email|E-Mail)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:email'), 
            5 => array(
                    '/^(Tech|Technical)(\-| )(Contact )?ID(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:handle', 
                    '/^(Tech|Technical)(\-| )(Contact )?Name(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/^(Tech|Technical)(\-| )(Contact )?Organization(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:organization', 
                    '/^(Tech|Technical)(\-| )(Contact )?(Street|Address)[0-9]*(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:address', 
                    '/^(Tech|Technical)(\-| )(Contact )?City(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:city', 
                    '/^(Tech|Technical)(\-| )(Contact )?State\/Province(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:state', 
                    '/^(Tech|Technical)(\-| )(Contact )?Postal(\-| )Code(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:zipcode', 
                    '/^(Tech|Technical)(\-| )(Contact )?ZIP(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:zipcode', 
                    '/^(Tech|Technical)(\-| )(Contact )?Country(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:country', 
                    '/^(Tech|Technical)(\-| )(Contact )?Phone(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/^(Tech|Technical)(\-| )(Contact )?FAX(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:fax', 
                    '/^(Tech|Technical)(\-| )(Contact )?(Email|E-Mail)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email'), 
            6 => array(
                    '/^(Name Server|Name Server Name|Nameservers)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'nameserver', 
                    '/^DNSSEC(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'dnssec'), 
            7 => array('/^CED ID(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:ced:handle', 
                    '/^CED CC Locality(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:ced:country', 
                    '/^CED Type of Legal Entity(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:ced:type', 
                    '/^CED Type \(Other\)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:ced:type_description', 
                    '/^CED Form of Identification(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:ced:identification_form', 
                    '/^CED Form of ID \(Other\)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:ced:identification_description', 
                    '/^CED Identification Number(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:ced:id'), 
            8 => array('/^Registration Date(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/^Created On(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/^Expires On(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/^Expiration Date(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/^Updated On(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/^DNSSEC(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'dnssec'), 
            9 => array('/^Zone ID(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:zone:handle', 
                    '/^Zone Name(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:zone:name', 
                    '/^Zone Organization(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:zone:organization', 
                    '/^Zone (Street|Address)[0-9]*(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:zone:address', 
                    '/^Zone City(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:zone:city', 
                    '/^Zone State\/Province(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:zone:state', 
                    '/^Zone Postal Code(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:zone:zipcode', 
                    '/^Zone Country(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:zone:country', 
                    '/^Zone Phone(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:zone:phone', 
                    '/^Zone FAX(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:zone:fax', 
                    '/^Zone (Email|E-Mail)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:zone:email'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/(Status: free|no matching record)|(DOMAIN NOT FOUND|NOT FOUND)|(Domain Status: Available)/i';

    /**
     * After parsing do something
     *
     * Clear empty lines at address and nameservers, also set dnssec
     * If there was another whois server call it for further information
     *
     * @param  object &$WhoisParser
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
        
        if (strtolower($ResultSet->dnssec) === 'unsigned' || $ResultSet->dnssec == '') {
            $ResultSet->dnssec = false;
        } else {
            $ResultSet->dnssec = true;
        }
        
        // check if there was another whois server
        if (isset($ResultSet->ask_whois)) {
            $Config = $WhoisParser->getConfig();
            
            $newConfig = $Config->get(trim($ResultSet->ask_whois));
            $newConfig['server'] = trim($ResultSet->ask_whois);
            unset($ResultSet->ask_whois);
            
            $Config->setCurrent($newConfig);
            $WhoisParser->call();
        }
    }
}