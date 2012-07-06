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
 * Template for Gtld_enom
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Gtld_enom extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(
            1 => '/Administrative Contact:(?>[\x20\t]*)(.*?)(?=Technical Contact:)/is', 
            2 => '/Technical Contact:(?>[\x20\t]*)(.*?)(?=Registrant Contact:|Status:)/is', 
            3 => '/Registrant Contact:(?>[\x20\t]*)(.*?)(?=Status:|Administrative Contact:)/is', 
            4 => '/Status:(?>[\x20\t]*)(.*?)(?=Name Servers)/is', 
            5 => '/Name Servers:(?>[\x20\t]*)(.*?)(?=Creation date)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/Administrative Contact:(?>[\x20\t]*)(.+)/is' => 'contacts:admin:address'), 
            2 => array('/Technical Contact:(?>[\x20\t]*)(.+)/is' => 'contacts:tech:address'), 
            3 => array('/Registrant Contact:(?>[\x20\t]*)(.+)/is' => 'contacts:owner:address'), 
            4 => array('/Status:(?>[\x20\t]*)(.+)$/im' => 'status'), 
            5 => array('/Name Servers:[\r\n](?>[\x20\t]*)(.*)$/is' => 'nameserver'));

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
        $filteredNameserver = array();
        
        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                if (! is_array($contactObject->address)) {
                    $explodedAddress = explode("\n", trim($contactObject->address));
                    
                    if (sizeof($explodedAddress) == 6) {
                        $explodedAddress = array_merge(array(0 => ''), $explodedAddress);
                    }
                    
                    if (isset($explodedAddress[0])) {
                        $contactObject->organization = trim($explodedAddress[0]);
                    }
                    if (isset($explodedAddress[1])) {
                        preg_match('/(.*)\((.*)\)/', $explodedAddress[1], $matchesEmail);
                        $contactObject->name = trim($matchesEmail[1]);
                        $contactObject->email = $matchesEmail[2];
                    }
                    if (isset($explodedAddress[2])) {
                        $contactObject->phone = trim($explodedAddress[2]);
                    }
                    if (isset($explodedAddress[3])) {
                        $contactObject->fax = trim(str_replace('Fax:', '', $explodedAddress[3]));
                    }
                    if (isset($explodedAddress[4])) {
                        $contactObject->address = trim($explodedAddress[4]);
                    }
                    if (isset($explodedAddress[5]) && sizeof($explodedAddress) == 7) {
                        preg_match('/(.*),(.*) ([0-9]*)/', $explodedAddress[5], $matchesCity);
                        $contactObject->city = trim($matchesCity[1]);
                        $contactObject->state = trim($matchesCity[2]);
                        $contactObject->zipcode = trim($matchesCity[3]);
                    }
                    if (isset($explodedAddress[6]) && sizeof($explodedAddress) == 7) {
                        $contactObject->country = trim($explodedAddress[6]);
                    }
                    if (isset($explodedAddress[6]) && sizeof($explodedAddress) == 8) {
                        preg_match('/(.*),(.*) ([0-9]*)/', $explodedAddress[6], $matchesCity);
                        $contactObject->city = trim($matchesCity[1]);
                        $contactObject->state = trim($matchesCity[2]);
                        $contactObject->zipcode = trim($matchesCity[3]);
                    }
                    if (isset($explodedAddress[7])) {
                        $contactObject->country = trim($explodedAddress[7]);
                    }
                    
                    $explodedAddress = array();
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