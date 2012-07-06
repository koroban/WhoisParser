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
 * Template for .HK
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Hk extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(
            1 => '/Registrant Contact Information:(.*?)(?=Administrative Contact Information)/is', 
            2 => '/Administrative Contact Information:(?>[\x20\t]*)(.*?)(?=Technical Contact Information)/is', 
            3 => '/Technical Contact Information:(?>[\x20\t]*)(.*?)(?=Name Servers Information)/is', 
            4 => '/Name Servers Information:(?>[\x20\t]*)(.*?)$/is', 
            5 => '/Registrar Name:(?>[\x20\t]*)(.*?)(?=Registrant Contact Information)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^Company English Name(.*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/Address:(?>[\x20\t]*)(.+)(?=Country)/is' => 'contacts:owner:address', 
                    '/^Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:country', 
                    '/^Email:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:email', 
                    '/^Domain Name Commencement Date:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/^Expiry Date:(?>[\x20\t]*)(.+)$/im' => 'expires'), 
            2 => array('/^Given name:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/^Family name:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/^Company name:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:organization', 
                    '/Address:(?>[\x20\t]*)(.+)(?=Country)/is' => 'contacts:admin:address', 
                    '/^Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:country', 
                    '/^Phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone', 
                    '/^Fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:fax', 
                    '/^Email:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:email', 
                    '/^Account Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:handle'), 
            3 => array('/^Given name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/^Family name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/^Company name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:organization', 
                    '/Address:(?>[\x20\t]*)(.+)(?=Country)/is' => 'contacts:tech:address', 
                    '/^Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:country', 
                    '/^Phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/^Fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:fax', 
                    '/^Email:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email', 
                    '/^Account Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:handle'), 
            4 => array(
                    '/Name Servers Information:\r\n(?>[\x20\t]*)(.*?)[\r\n]{3}/is' => 'nameserver'), 
            5 => array('/^Registrar Name:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/^Registrar Contact Information: Email:(?>[\x20\t]*)(.+)$/im' => 'registrar:email'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/The domain has not been registered./i';

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