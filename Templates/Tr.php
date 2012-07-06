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
 * Template for .TR
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
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
    protected $blocks = array(1 => '/Registrant:[\r\n](.*?)(?=\*\* Administrative Contact)/is', 
            2 => '/Administrative Contact:[\r\n](.*?)(?=Technical Contact)/is', 
            3 => '/Technical Contact:[\r\n](.*?)(?=Billing Contact)/is', 
            4 => '/Billing Contact:[\r\n](.*?)(?=Domain Servers)/is', 
            5 => '/Domain Servers:[\r\n](.*?)(?=\*\* Additional Info)/is', 
            6 => '/Additional Info:[\r\n](.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/Registrant:[\r\n](.+)$/is' => 'contacts:owner:address'), 
            2 => array('/^NIC Handle(?>[\x20\t]*): (.+)$/im' => 'contacts:admin:handle', 
                    '/^Organization Name(?>[\x20\t]*): (.*)$/im' => 'contacts:admin:organization', 
                    '/Address(?>[\x20\t]*): (.+)(?=Phone)/is' => 'contacts:admin:address', 
                    '/^Phone(?>[\x20\t]*): (.+)$/im' => 'contacts:admin:phone', 
                    '/^Fax(?>[\x20\t]*): (.+)$/im' => 'contacts:admin:fax'), 
            3 => array('/^NIC Handle(?>[\x20\t]*): (.+)$/im' => 'contacts:tech:handle', 
                    '/^Organization Name(?>[\x20\t]*): (.*)$/im' => 'contacts:tech:organization', 
                    '/Address(?>[\x20\t]*): (.+)(?=Phone)/is' => 'contacts:tech:address', 
                    '/^Phone(?>[\x20\t]*): (.+)$/im' => 'contacts:tech:phone', 
                    '/^Fax(?>[\x20\t]*): (.+)$/im' => 'contacts:tech:fax'), 
            4 => array('/^NIC Handle(?>[\x20\t]*): (.+)$/im' => 'contacts:billing:handle', 
                    '/^Organization Name(?>[\x20\t]*): (.*)$/im' => 'contacts:billing:organization', 
                    '/Address(?>[\x20\t]*): (.+)(?=Phone)/is' => 'contacts:billing:address', 
                    '/^Phone(?>[\x20\t]*): (.+)$/im' => 'contacts:billing:phone', 
                    '/^Fax(?>[\x20\t]*): (.+)$/im' => 'contacts:billing:fax'), 
            5 => array('/^Domain Servers:[\r\n](.*?)$/is' => 'nameserver'), 
            6 => array('/^Created on(?>[\.]*): (.+)$/im' => 'created', 
                    '/^Expires on(?>[\.]*): (.+)$/im' => 'expires'));

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
     * @param  object $whoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        $filteredNameserver = array();
        $filteredAddress = array();
        
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
        
        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                $contactObject->organization = utf8_encode($contactObject->organization);
                
                if (is_array($contactObject->address)) {
                    foreach ($contactObject->address as $key => $value) {
                        if (trim($line) != '' && $contactType != 'owner') {
                            $filteredAddress[] = utf8_encode($value);
                        }
                    }
                    
                    $contactObject->address = $filteredAddress;
                    $filteredAddress = array();
                } else {
                    $explodedAddress = explode("\n", $contactObject->address);
                    
                    foreach ($explodedAddress as $key => $line) {
                        if (trim($line) != '' && $contactType != 'owner') {
                            $filteredAddress[] = utf8_encode(trim($line));
                        } elseif ($contactType == 'owner') {
                            $filteredAddress[] = utf8_encode(trim($line));
                        }
                    }
                    
                    $contactObject->address = $filteredAddress;
                    $filteredAddress = array();
                }
                
                if ($contactType == 'owner') {
                    if (isset($contactObject->address[0])) {
                        $contactObject->organization = $contactObject->address[0];
                    }
                    if (isset($contactObject->address[6])) {
                        $contactObject->phone = $contactObject->address[6];
                    }
                    if (isset($contactObject->address[7])) {
                        $contactObject->fax = $contactObject->address[7];
                    }
                    if (isset($contactObject->address[4])) {
                        $contactObject->country = $contactObject->address[4];
                    }
                    if (isset($contactObject->address[2])) {
                        $contactObject->city = $contactObject->address[2];
                    }
                    if (isset($contactObject->address[5])) {
                        $contactObject->email = $contactObject->address[5];
                    }
                    if (isset($contactObject->address[1])) {
                        $contactObject->address = $contactObject->address[1];
                    }
                }
            }
        }
    }
}