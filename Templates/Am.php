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
 * Template for .AM
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Am extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(
            1 => '/(?>[\x20\t]*)Domain name:(?>[\x20\t]*)(.*?)(?=Registrant\:)/is', 
            2 => '/(?>[\x20\t]*)Registrant:(?>[\x20\t]*)(.*?)(?=Administrative contact)/is', 
            3 => '/(?>[\x20\t]*)Administrative contact:(?>[\x20\t]*)(.*?)(?=Technical contact)/is', 
            4 => '/(?>[\x20\t]*)Technical contact:(?>[\x20\t]*)(.*?)(?=DNS servers)/is', 
            5 => '/(?>[\x20\t]*)DNS servers:(?>[\x20\t]*)(.*?)(?=Registered)/is', 
            6 => '/(?>[\x20\t]*)Registered:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/(?>[\x20\t]*)Registrar:(?>[\x20\t]*)(.*?)$/im' => 'registrar:name', 
                    '/(?>[\x20\t]*)Status:(?>[\x20\t]*)(.*?)$/im' => 'status'), 
            2 => array(
                    '/(?>[\x20\t]*)Registrant:[\r\n]{1,2}(?>[\x20\t]*)(.*?)[\n]{2}/is' => 'contacts:owner:address'), 
            3 => array(
                    '/(?>[\x20\t]*)Administrative contact:[\r\n]{1,2}(?>[\x20\t]*)(.*?)[\n]{2}/is' => 'contacts:admin:address'), 
            4 => array(
                    '/(?>[\x20\t]*)Technical Contact:[\r\n]{1,2}(?>[\x20\t]*)(.*?)[\n]{2}/is' => 'contacts:tech:address'), 
            5 => array(
                    '/(?>[\x20\t]*)DNS servers:[\r\n]{1,2}(?>[\x20\t]*)(.*?)$/is' => 'nameserver'), 
            6 => array('/^(?>[\x20\t]*)Registered:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/^(?>[\x20\t]*)Last modified:(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/^(?>[\x20\t]*)Expires:(?>[\x20\t]*)(.+)$/im' => 'expires'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No match/i';

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
                    
                    $contactObject->address = $filteredAddress;
                    $filteredAddress = array();
                }
            }
        }
        
        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            switch ($contactType) {
                case 'owner':
                    foreach ($contactArray as $contactObject) {
                        $contactObject->organization = $contactObject->address[0];
                        
                        $explodedAddress = explode(',', $contactObject->address[2]);
                        
                        if (sizeof($explodedAddress) == 2) {
                            $contactObject->city = trim($explodedAddress[0]);
                            $contactObject->zipcode = trim($explodedAddress[1]);
                        } else {
                            $contactObject->city = trim($explodedAddress[0]);
                            $contactObject->state = trim($explodedAddress[1]);
                            $contactObject->zipcode = trim($explodedAddress[2]);
                        }
                        
                        $contactObject->country = $contactObject->address[3];
                        $contactObject->address = $contactObject->address[1];
                    }
                    break;
                case 'admin':
                case 'tech':
                    foreach ($contactArray as $contactObject) {
                        $contactObject->name = $contactObject->address[0];
                        $contactObject->organization = $contactObject->address[1];
                        $contactObject->country = $contactObject->address[4];
                        $contactObject->email = $contactObject->address[5];
                        $contactObject->phone = $contactObject->address[6];
                        $contactObject->fax = $contactObject->address[7];
                        
                        $explodedAddress = explode(',', $contactObject->address[3]);
                        
                        if (sizeof($explodedAddress) == 2) {
                            $contactObject->city = trim($explodedAddress[0]);
                            $contactObject->zipcode = trim($explodedAddress[1]);
                        } else {
                            $contactObject->city = trim($explodedAddress[0]);
                            $contactObject->state = trim($explodedAddress[1]);
                            $contactObject->zipcode = trim($explodedAddress[2]);
                        }
                        
                        $contactObject->address = $contactObject->address[2];
                    }
                    break;
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