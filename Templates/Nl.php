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
 * Template for .FR
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Nl extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Domain name:(?>[\x20\t]*)(.*?)(?=Registrant|Registrar)/is', 
            2 => '/Registrant:(?>[\x20\t]*)(.*?)(?=Administrative contact)/is', 
            3 => '/Administrative contact:(?>[\x20\t]*)(.*?)(?=Registrar)/is', 
            4 => '/Registrar:(?>[\x20\t]*)(.*?)(?=(Technical contact\(s\)|DNSSEC))/is', 
            5 => '/Technical contact\(s\):(?>[\x20\t]*)(.*?)(?=DNSSEC)/is', 
            6 => '/DNSSEC:(?>[\x20\t]*)(.*?)(?=Domain nameservers)/is', 
            7 => '/Domain nameservers:(?>[\x20\t]*)(.*?)(?=(Date registered|Record maintained))/is', 
            8 => '/Date registered:(?>[\x20\t]*)(.*?)(?=Record maintained)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(1 => array('/status:(?>[\x20\t]*)(.+)$/im' => 'status'), 
            
            2 => array('/Registrant:[\n](?>[\x20\t]*)(.+)$/is' => 'contacts:owner:address'), 
            3 => array(
                    '/Administrative contact:[\n](?>[\x20\t]*)(.+)$/is' => 'contacts:admin:address'), 
            4 => array('/Registrar:[\n](?>[\x20\t]*)(.+)$/is' => 'registrar:name'), 
            5 => array(
                    '/Technical contact\(s\):[\n](?>[\x20\t]*)(.*?)$/is' => 'contacts:tech:address'), 
            6 => array('/DNSSEC:(?>[\x20\t]*)(.+)$/im' => 'dnssec'), 
            7 => array('/Domain nameservers:[\n](?>[\x20\t]*)(.+)$/is' => 'nameserver'), 
            8 => array('/Date registered:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/Date of last change:(?>[\x20\t]*)(.+)$/im' => 'changed'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/is free/i';

    /**
     * After parsing ...
     * 
     * Fix address, registrar, dnssec and nameservers
     * 
	 * @param  object &$WhoisParser
	 * @return void
	 */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        $filteredNameserver = array();
        $filteredAddress = array();
        
        if ($ResultSet->dnssec != 'no') {
            $ResultSet->dnssec = true;
        } else {
            $ResultSet->dnssec = false;
        }
        
        if (isset($ResultSet->registrar->name)) {
            $explodedRegistrar = explode("\n", $ResultSet->registrar->name);
            $ResultSet->registrar->name = trim($explodedRegistrar[0]);
        }
        
        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                if (! is_array($contactObject->address)) {
                    $explodedAddress = explode("\n", $contactObject->address);
                    
                    foreach ($explodedAddress as $key => $value) {
                        $value = trim($value);
                        
                        if ($value != '') {
                            $filteredAddress[] = $value;
                        }
                    }
                    
                    if (sizeof($filteredAddress) == 4) {
                        $contactObject->handle = $filteredAddress[0];
                        $contactObject->name = $filteredAddress[1];
                        $contactObject->phone = $filteredAddress[2];
                        $contactObject->email = $filteredAddress[3];
                        $contactObject->address = '';
                    }
                    
                    if (sizeof($filteredAddress) == 5) {
                        $contactObject->handle = $filteredAddress[0];
                        $contactObject->name = $filteredAddress[1];
                        $contactObject->address = $filteredAddress[2];
                        $contactObject->phone = $filteredAddress[3];
                        $contactObject->email = $filteredAddress[4];
                    }
                    
                    $filteredAddress = array();
                }
            }
        }
        
        if (isset($ResultSet->nameserver) && $ResultSet->nameserver != '' &&
                 ! is_array($ResultSet->nameserver)) {
            
            $explodedNameserver = explode("\n", $ResultSet->nameserver);
            foreach ($explodedNameserver as $key => $line) {
                $line = trim($line);
                
                if ($line != '') {
                    preg_match('/(.*) ([0-9a-z\.\:]*)/im', $line, $matches);
                    
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