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
 * Template for Cocca Domains
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Cocca extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Domain Information[\r\n](.*?)[\n]{2}/is', 
            2 => '/Registrar Information[\r\n](.*?)[\n]{2}/is', 
            3 => '/Registrant:[\r\n](.*?)[\r\n]{2}/is', 
            4 => '/(Admin|Administrative) Contact:[\r\n](.*?)[\n]{2}/is', 
            5 => '/Technical Contact:[\r\n](.*?)[\n]{2}/is', 
            6 => '/Billing Contact:[\r\n](.*?)[\n]{2}/is', 
            7 => '/Nameserver Information:[\r\n](.*?)[\n]{2}/is', 
            8 => '/Original Creation Date:(?>[\x20\t]*)(.*?)[\n]{2}/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/Name Servers:[\r\n](?>[\x20\t]*)(.*)$/is' => 'nameserver', 
                    '/^Status: (.+)$/im' => 'status', '/^Created: (.+)$/im' => 'created', 
                    '/^Modified: (.+)$/im' => 'changed', '/^Expires: (.+)$/im' => 'expires'), 
            
            2 => array('/^Registrar Name:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/^Registration URL:(?>[\x20\t]*)(.+)$/im' => 'registrar:url', 
                    '/^Customer Service contacts:(?>[\x20\t]*)(.+)$/im' => 'registrar:email', 
                    '/^Customer Service Email:(?>[\x20\t]*)(.+)$/im' => 'registrar:email'), 
            
            3 => array('/^Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/^(Company|Organisation):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization', 
                    '/^Email( Address)*:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:email', 
                    '/Address:[\r\n](?>[\x20\t]*)(.+)(?=Email Address|Email|Phone Number)/is' => 'contacts:owner:address', 
                    '/^Address:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address', 
                    '/^Phone Number:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:phone', 
                    '/^City:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:city', 
                    '/^Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:country', 
                    '/^Postal Code:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:zipcode', 
                    '/^Fax( Number)*:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:fax'), 
            
            4 => array('/^Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/^(Company|Organisation):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:organization', 
                    '/^Email( Address)*:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:email', 
                    '/Address:[\r\n](?>[\x20\t]*)(.+)(?=Email)/is' => 'contacts:admin:address', 
                    '/^Address:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:address', 
                    '/^City:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:city', 
                    '/^Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:country', 
                    '/^Postal Code:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:zipcode', 
                    '/^Phone( Number)*:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone', 
                    '/^Fax( Number)*:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:fax'), 
            
            5 => array('/^Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/^(Company|Organisation):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:organization', 
                    '/^Email( Address)*:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email', 
                    '/Address:[\r\n](?>[\x20\t]*)(.+)(?=Email)/is' => 'contacts:tech:address', 
                    '/^Address:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:address', 
                    '/^City:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:city', 
                    '/^Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:country', 
                    '/^Postal Code:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:zipcode', 
                    '/^Phone( Number)*:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/^Fax( Number)*:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:fax'), 
            
            6 => array('/^Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:name', 
                    '/^Email Address:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:email', 
                    '/Address:[\r\n](?>[\x20\t]*)(.+)(?=Email)/is' => 'contacts:billing:address', 
                    '/^Phone Number:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:phone', 
                    '/^Fax Number:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:fax'), 
            
            7 => array('/^Nameserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver'), 
            8 => array('/^Original Creation Date:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/^Expiration Date:(?>[\x20\t]*)(.+)$/im' => 'expires'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/(Status: Not Registered|Domain does not exist)/i';

    /**
     * After parsing ...
     * 
     * Fix address and nameserver in whois output
     * 
     * @param  object $whoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        $filteredAddress = array();
        $filteredNameserver = array();
        
        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                if (! is_array($contactObject->address)) {
                    $explodedAddress = explode("\n", $contactObject->address);
                    
                    foreach ($explodedAddress as $key => $line) {
                        if (trim($line) != '' && ! preg_match('/Email/', $line)) {
                            $filteredAddress[] = trim($line);
                        }
                    }
                    
                    $contactObject->address = $filteredAddress;
                    $filteredAddress = array();
                }
            }
        }
        
        if (isset($ResultSet->nameserver) && $ResultSet->nameserver != '' &&
                 ! is_array($ResultSet->nameserver)) {
            $explodedNameserver = explode("\n", $ResultSet->nameserver);
            foreach ($explodedNameserver as $key => $line) {
                if (trim($line) != '') {
                    $filteredNameserver[] = strtolower(trim($line));
                }
            }
            $ResultSet->nameserver = $filteredNameserver;
        }
    }
}