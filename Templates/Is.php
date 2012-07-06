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
 * Template for .IS
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Is extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/domain:(?>[\x20\t]*)(.*?)(?=(person|role):)/is', 
            2 => '/(person|role):(?>[\x20\t]*)(.*?)([\n]{2}|$)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^status:(?>[\x20\t]*)(.+)$/im' => 'status', 
                    '/^admin-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:admin', 
                    '/^tech-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:tech', 
                    '/^zone-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:zone', 
                    '/^billing-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:billing', 
                    '/^nserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver', 
                    '/^created:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/^expires:(?>[\x20\t]*)(.+)$/im' => 'expires'), 
            2 => array('/^nic-hdl:(?>[\x20\t]*)(.+)$/im' => 'contacts:handle', 
                    '/^(person|role):(?>[\x20\t]*)(.+)$/im' => 'contacts:name', 
                    '/^address:(?>[\x20\t]*)(.+)$/im' => 'contacts:address', 
                    '/^phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:phone', 
                    '/^fax-no:(?>[\x20\t]*)(.+)$/im' => 'contacts:fax', 
                    '/^e-mail:(?>[\x20\t]*)(.+)$/im' => 'contacts:email', 
                    '/^changed:(?>[\x20\t]*)(.+)$/im' => 'contacts:changed'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No entries found for query/i';

    /**
     * After parsing ...
     *
     * Convert UTF-8 in contact handles and rawdata
     *
     * @param  object $whoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        $filteredAddress = array();
        $filteredRawdata = array();
        
        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                $contactObject->name = utf8_encode($contactObject->name);
                
                if (is_array($contactObject->address)) {
                    foreach ($contactObject->address as $key => $value) {
                        $filteredAddress[] = utf8_encode($value);
                    }
                    
                    $contactObject->address = $filteredAddress;
                    $filteredAddress = array();
                } else {
                    $contactObject->address = utf8_encode($contactObject->address);
                }
            }
        }
        
        if (is_array($ResultSet->rawdata)) {
            foreach ($ResultSet->rawdata as $key => $line) {
                $filteredRawdata[] = utf8_encode($line);
            }
            
            $ResultSet->rawdata = $filteredRawdata;
        }
    }
}