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
 * Template for IANA #2, #69 
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Gtld_networksolutions extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(
            1 => '/Registrant( \[[0-9]*\]:|:)(.*?)(?=Registrar Name|Domain Name:|Registrar:|Administrative Contact)/is', 
            2 => '/Administrative( Contact| Contact, Technical Contact|,[ ]{1,}Technical Contact)( \[[0-9]*\]:|:)(.*)(?=Technical[ ]{1,}Contact|Billing Contact|Record created|Record updated on|Record expires on|Registrar of Record|Registration Service Provider|Domain servers in listed order)/isU', 
            3 => '/Technical[ ]{1,}Contact( \[[0-9]*\]:|:)(.*?)(?=Administrative contact|Record last updated|Record created|Record updated on|Record expires on|Registrar of Record|Registration Service Provider|Domain servers in listed order|Domain name servers in listed order|DNS Servers|Name Servers)/is', 
            4 => '/Database last updated on (.*?)$/im', 
            5 => '/(Domain servers in listed order|DNS Servers):[\n]{2}(?>[\x20\t]*)(.*?)\n\n/is', 
            6 => '/Record created on:(.*?)$/is', 
            7 => '/Billing[ ]{1,}Contact( \[[0-9]*\]:|:)(.*?)(?=Technical Contact|Domain servers in listed order|Record created on)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/Registrant( \[[0-9]*\]:|:)(.*?)$/is' => 'contacts:owner:address'), 
            2 => array(
                    '/Administrative( Contact| Contact, Technical Contact|,[ ]{1,}Technical Contact)( \[[0-9]*\]:|:)(.*)$/is' => 'contacts:admin:address'), 
            3 => array(
                    '/Technical[ ]{1,}Contact( \[[0-9]*\]:|:)(.*?)$/is' => 'contacts:tech:address'), 
            4 => array('/Database last updated on (.*?)$/is' => 'changed'), 
            5 => array('/[^Domain servers in listed order] .* (.*)$/im' => 'ips'), 
            6 => array('/Record created on:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/Database last updated on:(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/Domain Expires on:(?>[\x20\t]*)(.+)$/im' => 'expires'), 
            7 => array(
                    '/Billing[ ]{1,}Contact( \[[0-9]*\]:|:)(.*?)$/is' => 'contacts:billing:address'));

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
                $filteredAddress = array_map('trim', explode("\n", trim($contactObject->address)));
                $lastEntry = end($filteredAddress);
                $sizeOfAddress = sizeof($filteredAddress);
                
                // try to determine if an email address is in the first line
                preg_match('/(?>[\x20\t]*)([a-z0-9\.\-, ]*)(?>[\x20\t]{1,})(.*@.*)/i', $filteredAddress[0], $matches);
                
                // if there is no email address in the first line, then we
                // assume it is the name
                if (sizeof($matches) === 0) {
                    $contactObject->name = $filteredAddress[0];
                } else {
                    if (isset($matches[1])) {
                        $contactObject->name = trim($matches[1]);
                    }
                    
                    if (isset($matches[2])) {
                        $contactObject->email = trim($matches[2]);
                    }
                }
                
                // try to determine if an email address is in the second
                // line
                preg_match('/(?>[\x20\t]*)([a-z0-9\.\-, ]*)(?>[\x20\t]{1,})(.*@.*)/i', $filteredAddress[1], $matches);
                
                // if there is no email address in the first line, then we
                // assume it is the organization
                if (sizeof($matches) === 0) {
                    $contactObject->organization = $filteredAddress[1];
                } else {
                    if (isset($matches[1])) {
                        $contactObject->organization = trim($matches[1]);
                    }
                    
                    if (isset($matches[2])) {
                        $contactObject->email = trim($matches[2]);
                    }
                }
                
                // check if last entry contains keyword 'fax'
                if (stripos($lastEntry, 'fax') !== false) {
                    // regex for fax number
                    preg_match('/([0-9\-\+\.\/ ]*)(?>[\x20\t]*)fax:(?>[\x20\t]*)([ 0-9\-\+\.\/]*)/i', $lastEntry, $matches);
                    
                    // if the regex doesn't match, just set the number to fax
                    // and
                    // use the entry before as phone number
                    if (sizeof($matches) === 0) {
                        $contactObject->fax = str_replace('Fax.', '', $lastEntry);
                        $contactObject->phone = str_replace('Tel.', '', $filteredAddress[$sizeOfAddress -
                                 2]);
                    } else {
                        // if regex hits and the got a phone number set it
                        if (isset($matches[1]) && trim($matches[1]) != '') {
                            $contactObject->phone = trim($matches[1]);
                        } elseif (isset($matches[1])) {
                            $contactObject->phone = trim(str_replace(array('Phone:', 'Tel:'), '', $filteredAddress[$sizeOfAddress -
                                     2]));
                        }
                        
                        // set fax number
                        if (isset($matches[2])) {
                            $contactObject->fax = trim($matches[2]);
                        }
                    }
                    // check if last entry contains keyword 'email'
                } elseif (stripos($lastEntry, 'email') !== false) {
                    // move backwards to get phone number
                    if (stripos($filteredAddress[$sizeOfAddress - 2], 'fax') !== false) {
                        $contactObject->fax = trim(str_replace(array('Fax:', 'Fax..:'), '', $filteredAddress[$sizeOfAddress -
                                 2]));
                        if (stripos($filteredAddress[$sizeOfAddress - 3], 'phone') !== false) {
                            $contactObject->phone = trim(str_replace(array('Phone:', 'Tel:'), '', $filteredAddress[$sizeOfAddress -
                                     3]));
                        }
                    } else {
                        $contactObject->phone = trim(str_replace(array('Phone:', 'Tel:'), '', $filteredAddress[$sizeOfAddress -
                                 2]));
                    }
                    
                    $contactObject->email = trim(str_replace('Email:', '', $lastEntry));
                    // check if last entry contains keyword 'phone'
                } elseif (stripos($lastEntry, 'Phone') !== false) {
                    $contactObject->phone = trim(str_replace(array('Phone:', 'Tel:'), '', $lastEntry));
                    // check if last entry contains an email address without
                    // keyword
                } elseif (preg_match('/.*@.*/', $lastEntry, $matches)) {
                    if (isset($matches[0])) {
                        $contactObject->email = trim($matches[0]);
                    }
                    // in some cases the last entry is the phone number, but
                    // only if it is not the owner contact
                } elseif ($contactType !== 'owner') {
                    $contactObject->phone = $lastEntry;
                }
                
                // some special cases for different sizes of addresses
                if ($sizeOfAddress <= 4) {
                    $contactObject->address = $filteredAddress[1];
                    $contactObject->city = $filteredAddress[2];
                    $contactObject->country = $filteredAddress[3];
                } elseif ($sizeOfAddress === 5 && strlen($filteredAddress[4]) === 2) {
                    $contactObject->address = $filteredAddress[2];
                    $contactObject->city = $filteredAddress[3];
                    $contactObject->country = $filteredAddress[4];
                } elseif ($sizeOfAddress === 5 && strlen($filteredAddress[3]) === 2) {
                    $contactObject->address = $filteredAddress[1];
                    $contactObject->city = $filteredAddress[2];
                    $contactObject->country = $filteredAddress[3];
                } elseif (isset($filteredAddress[5]) && strlen($filteredAddress[5]) === 2 &&
                         $sizeOfAddress < 9) {
                    $contactObject->address = array($filteredAddress[2], $filteredAddress[3]);
                    $contactObject->city = $filteredAddress[4];
                    $contactObject->country = $filteredAddress[5];
                    
                    if ($contactObject->email == '' && isset($filteredAddress[6])) {
                        $contactObject->email = $filteredAddress[6];
                    }
                } elseif (isset($filteredAddress[3]) && strlen($filteredAddress[3]) === 2 &&
                         $sizeOfAddress === 6) {
                    $contactObject->address = $filteredAddress[1];
                    $contactObject->city = $filteredAddress[2];
                    $contactObject->country = $filteredAddress[3];
                } elseif (isset($filteredAddress[7]) && strlen($filteredAddress[7]) === 2) {
                    $contactObject->address = array($filteredAddress[2], $filteredAddress[3]);
                    $contactObject->city = $filteredAddress[4];
                    $contactObject->state = $filteredAddress[5];
                    $contactObject->zipcode = $filteredAddress[6];
                    $contactObject->country = $filteredAddress[7];
                } else {
                    $contactObject->address = $filteredAddress[2];
                    $contactObject->city = $filteredAddress[3];
                    $contactObject->country = $filteredAddress[4];
                }
            }
        }
    }
}