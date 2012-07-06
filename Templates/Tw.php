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
 * Template for .TW
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Tw extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(
            1 => '/(?>[\x20\t]*)Registrant:(?>[\x20\t]*)(.*?)(?=Administrative Contact\:|Contact\:)/is', 
            2 => '/(?>[\x20\t]*)(Administrative Contact|Contact):(?>[\x20\t]*)(.*?)(?=Technical Contact|Record expires on)/is', 
            3 => '/(?>[\x20\t]*)Technical Contact:(?>[\x20\t]*)(.*?)(?=Record expires on)/is', 
            4 => '/(?>[\x20\t]*)Record expires on(?>[\x20\t]*)(.*?)(?=Domain servers in listed)/is', 
            5 => '/(?>[\x20\t]*)Domain servers in listed(?>[\x20\t]*)(.*?)(?=Registration Service Provider)/is', 
            6 => '/(?>[\x20\t]*)Registration Service Provider(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array(
                    '/(?>[\x20\t]*)Registrant:[\r\n]{1,2}(.*?)[\r\n]{2}/is' => 'contacts:owner:address'), 
            2 => array(
                    '/(?>[\x20\t]*)(Administrative Contact|Contact):[\r\n]{1,2}(?>[\x20\t]*)(.*?)[\r\n]{2}/is' => 'contacts:admin:address'), 
            3 => array(
                    '/(?>[\x20\t]*)Technical Contact:[\r\n]{1,2}(.*?)[\r\n]{2}/is' => 'contacts:tech:address'), 
            4 => array(
                    '/^(?>[\x20\t]*)Record expires on(?>[\x20\t]*)(.+) \(YYYY\-MM\-DD\)$/im' => 'expires', 
                    '/^(?>[\x20\t]*)Record created on(?>[\x20\t]*)(.+) \(YYYY\-MM\-DD\)$/im' => 'created'), 
            5 => array(
                    '/(?>[\x20\t]*)Domain servers in listed order:[\r\n]{1,2}(?>[\x20\t]*)(.*?)$/is' => 'nameserver'), 
            6 => array(
                    '/^(?>[\x20\t]*)Registration Service Provider:(?>[\x20\t]*)(.+)$/im' => 'registrar:name'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No Found/i';

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
                
                switch ($contactType) {
                    case 'owner':
                        if (sizeof($contactObject->address) == 7) {
                            $contactObject->organization = $contactObject->address[0];
                            $contactObject->phone = $contactObject->address[2];
                            $contactObject->fax = $contactObject->address[3];
                            $contactObject->city = $contactObject->address[5];
                            $contactObject->country = $contactObject->address[6];
                            
                            preg_match('/^(.*) ([a-z0-9\-\.@_]*)$/im', $contactObject->address[1], $matches);
                            $contactObject->name = $matches[1];
                            $contactObject->email = $matches[2];
                            
                            $contactObject->address = $contactObject->address[4];
                        }
                        
                        if (sizeof($contactObject->address) == 3) {
                            $contactObject->organization = $contactObject->address[1];
                            $contactObject->address = explode(',', $contactObject->address[2]);
                            
                            foreach ($contactObject->address as $key => $line) {
                                $filteredAddress[] = trim($line);
                            }
                            
                            $contactObject->address = $filteredAddress;
                            $filteredAddress = array();
                        }
                        break;
                    case 'admin':
                    case 'tech':
                        preg_match('/^(.*) ([a-z0-9\-\.@_]*)$/im', $contactObject->address[0], $matches);
                        
                        if (empty($matches)) {
                            $contactObject->name = $contactObject->address[0];
                        }
                        
                        if (isset($matches[1])) {
                            $contactObject->name = $matches[1];
                        }
                        
                        if (isset($matches[2])) {
                            $contactObject->email = $matches[2];
                            
                            if (isset($contactObject->address[1])) {
                                $contactObject->phone = trim(str_replace('TEL:', '', $contactObject->address[1]));
                            }
                            
                            if (isset($contactObject->address[2])) {
                                $contactObject->fax = trim(str_replace('FAX:', '', $contactObject->address[2]));
                            }
                        } else {
                            $contactObject->email = $contactObject->address[1];
                        }
                        
                        $contactObject->address = '';
                        break;
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