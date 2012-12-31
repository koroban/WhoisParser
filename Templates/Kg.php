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
 * Template for .KG
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Kg extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(
            1 => '/Administrative Contact:(?>[\x20\t]*)(.*?)(?=Technical Contact)/is', 
            2 => '/Technical Contact:(?>[\x20\t]*)(.*?)(?=Billing Contact)/is', 
            3 => '/Billing Contact:(?>[\x20\t]*)(.*?)(?=Record created)/is', 
            4 => '/Record created(?>[\x20\t]*)(.*?)(?=Name servers in the listed order)/is', 
            5 => '/Name servers in the listed order(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array(
                    '/(?>[\x20\t]*)Administrative Contact:[\r\n]{1,2}(.*?)(?=phone)/is' => 'contacts:admin:address', 
                    '/phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone', 
                    '/fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:fax'), 
            2 => array(
                    '/(?>[\x20\t]*)Technical Contact:[\r\n]{1,2}(.*?)(?=phone)/is' => 'contacts:tech:address', 
                    '/phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:fax'), 
            3 => array(
                    '/(?>[\x20\t]*)Billing Contact:[\r\n]{1,2}(.*?)(?=phone)/is' => 'contacts:billing:address', 
                    '/phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:phone', 
                    '/fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:fax'), 
            4 => array('/Record created:(?>[\x20\t]*)(.*?)$/im' => 'created', 
                    '/Record last updated on (?>[\x20\t]*)(.*?)$/im' => 'changed', 
                    '/Record expires on (?>[\x20\t]*)(.*?)$/im' => 'expires'), 
            5 => array(
                    '/(?>[\x20\t]*)Name servers in the listed order:[\r\n]{1,2}(?>[\x20\t]*)(.*?)$/is' => 'nameserver'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/Data not found/i';

    /**
     * After parsing do something
     *
     * Fix address and nameservers
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
                        $filteredAddress[] = trim($line);
                    }
                }
                
                preg_match('/.* \(([0-9a-z\-]*)\)/im', $filteredAddress[0], $matches);
                $contactObject->handle = $matches[1];
                
                preg_match('/.* \([0-9a-z\-]*\),(?>[\x20\t]*)(.*)/im', $filteredAddress[0], $matches);
                $contactObject->email = $matches[1];
                
                preg_match('/(.*) \([0-9a-z\-]*\)/im', $filteredAddress[0], $matches);
                $contactObject->organization = $matches[1];
                
                $contactObject->address = $filteredAddress[1];
                
                $filteredAddress = array();
            }
        }
        
        if (isset($ResultSet->nameserver) && $ResultSet->nameserver != '' &&
                 ! is_array($ResultSet->nameserver)) {
            $explodedNameserver = explode("\n", $ResultSet->nameserver);
            foreach ($explodedNameserver as $key => $line) {
                $line = strtolower(trim($line));
                
                if ($line != '') {
                    preg_match('/(.*) ([0-9\.]*)/im', $line, $matches);
                    
                    if (sizeof($matches) == 0) {
                        $filteredNameserver[] = strtolower($line);
                    } else {
                        if (isset($matches[2])) {
                            $ips[] = $matches[2];
                        }
                        
                        $filteredNameserver[] = strtolower($matches[1]);
                    }
                }
            }
            $ResultSet->nameserver = $filteredNameserver;
            
            if (isset($ips)) {
                $ResultSet->ips = $ips;
            }
        }
    }
}