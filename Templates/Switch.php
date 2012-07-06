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
 * Template for Switch Domains .CH / .LI
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Switch extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Holder of domain name:[\n](.*?)[\n]{2}/is', 
            2 => '/Technical contact:[\n](.*?)[\n]{2}/is', 3 => '/DNSSEC:(.*?)[\n]{2}/is', 
            4 => '/Name servers:[\n](.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array(
                    '/Holder of domain name:[\n](?>[\x20\t]*)(.*)$/is' => 'contacts:owner:address'), 
            
            2 => array('/Technical contact:[\n](.*?)[\r\n]{2}/is' => 'contacts:tech:address'), 
            
            3 => array('/^DNSSEC:(?>[\x20\t]*)(.+)$/im' => 'dnssec'), 
            
            4 => array('/Name servers:[\n](?>[\x20\t]*)(.+)$/is' => 'nameserver'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/We do not have an entry in our database matching your query/i';

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
        
        if ($ResultSet->dnssec == 'N') {
            $ResultSet->dnssec = false;
        } else {
            $ResultSet->dnssec = true;
        }
        
        if (isset($ResultSet->contacts->owner) && is_array($ResultSet->contacts->owner)) {
            $size = sizeof($ResultSet->contacts->owner[0]->address);
            
            switch ($size) {
                case 6:
                    $ResultSet->contacts->owner[0]->organization = $ResultSet->contacts->owner[0]->address[0];
                    $ResultSet->contacts->owner[0]->name = $ResultSet->contacts->owner[0]->address[1];
                    $ResultSet->contacts->owner[0]->country = substr($ResultSet->contacts->owner[0]->address[3], 0, 2);
                    $ResultSet->contacts->owner[0]->address = array(
                            $ResultSet->contacts->owner[0]->address[2], 
                            substr($ResultSet->contacts->owner[0]->address[3], 3, strlen($ResultSet->contacts->owner[0]->address[3])));
                    break;
                case 7:
                    $ResultSet->contacts->owner[0]->organization = $ResultSet->contacts->owner[0]->address[0];
                    $ResultSet->contacts->owner[0]->name = $ResultSet->contacts->owner[0]->address[1];
                    $ResultSet->contacts->owner[0]->country = substr($ResultSet->contacts->owner[0]->address[4], 0, 2);
                    $ResultSet->contacts->owner[0]->address = array(
                            $ResultSet->contacts->owner[0]->address[3], 
                            substr($ResultSet->contacts->owner[0]->address[4], 3, strlen($ResultSet->contacts->owner[0]->address[4])));
                    break;
                default:
                    $ResultSet->contacts->owner[0]->name = $ResultSet->contacts->owner[0]->address[0];
                    $ResultSet->contacts->owner[0]->country = substr($ResultSet->contacts->owner[0]->address[2], 0, 2);
                    $ResultSet->contacts->owner[0]->address = array(
                            $ResultSet->contacts->owner[0]->address[1], 
                            substr($ResultSet->contacts->owner[0]->address[2], 3, strlen($ResultSet->contacts->owner[0]->address[2])));
            }
        }
        
        if (isset($ResultSet->contacts->tech) && is_array($ResultSet->contacts->tech)) {
            $size = sizeof($ResultSet->contacts->tech[0]->address);
            
            switch ($size) {
                case 6:
                    $ResultSet->contacts->tech[0]->organization = $ResultSet->contacts->tech[0]->address[0];
                    $ResultSet->contacts->tech[0]->name = $ResultSet->contacts->tech[0]->address[1];
                    $ResultSet->contacts->tech[0]->country = substr($ResultSet->contacts->tech[0]->address[4], 0, 2);
                    $ResultSet->contacts->tech[0]->address = array(
                            $ResultSet->contacts->tech[0]->address[3], 
                            substr($ResultSet->contacts->tech[0]->address[4], 3, strlen($ResultSet->contacts->tech[0]->address[4])));
                    break;
                default:
                    $ResultSet->contacts->tech[0]->organization = $ResultSet->contacts->tech[0]->address[0];
                    $ResultSet->contacts->tech[0]->name = $ResultSet->contacts->tech[0]->address[1];
                    $ResultSet->contacts->tech[0]->country = substr($ResultSet->contacts->tech[0]->address[3], 0, 2);
                    $ResultSet->contacts->tech[0]->address = array(
                            $ResultSet->contacts->tech[0]->address[2], 
                            substr($ResultSet->contacts->tech[0]->address[3], 3, strlen($ResultSet->contacts->tech[0]->address[3])));
            }
        }
    }
}