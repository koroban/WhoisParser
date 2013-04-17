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
 * Template for .EDU
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Edu extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Domain record activated:(.*?)$/is', 
            2 => '/Registrant:(.*?)(?=Administrative Contact)/is', 
            3 => '/Administrative Contact:(.*?)(?=Technical Contact)/is', 
            4 => '/Technical Contact:(.*?)(?=Name Servers)/is', 
            5 => '/Name Servers:(.*?)(?=Domain record activated)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^Domain record activated:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/^Domain record last updated:(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/^Domain expires:(?>[\x20\t]*)(.+)$/im' => 'expires'), 
            
            2 => array('/Registrant:[\n](?>[\x20\t]*)(.+)$/is' => 'contacts:owner:address'), 
            
            3 => array(
                    '/Administrative Contact:[\n](?>[\x20\t]*)(.+)$/is' => 'contacts:admin:address'), 
            
            4 => array('/Technical Contact:[\n](?>[\x20\t]*)(.+)$/is' => 'contacts:tech:address'), 
            
            5 => array('/^(?>[\x20\t]+)(.+)(?>[\x20\t]+)[0-9a-z\.\:]*$/im' => 'nameserver', 
                    '/^(?>[\x20\t]+).+(?>[\x20\t]+)([0-9a-z\.\:]*)$/im' => 'ips'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No Match/i';

    /**
     * After parsing ...
     *
     * Fix address
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        $filteredAddress = array();
        
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
                    
                    if (sizeof($filteredAddress) === 3) {
                        $contactObject->name = $filteredAddress[0];
                        $contactObject->city = $filteredAddress[1];
                        $contactObject->country = $filteredAddress[2];
                        $contactObject->address = '';
                    }
                    
                    if (sizeof($filteredAddress) === 5) {
                        $contactObject->org = $filteredAddress[0];
                        $contactObject->name = $filteredAddress[1];
                        $contactObject->address = $filteredAddress[2];
                        $contactObject->city = $filteredAddress[3];
                        $contactObject->country = $filteredAddress[4];
                    }
                    
                    if (sizeof($filteredAddress) === 7) {
                        $contactObject->name = $filteredAddress[0];
                        $contactObject->org = $filteredAddress[1];
                        $contactObject->address = $filteredAddress[2];
                        $contactObject->city = $filteredAddress[3];
                        $contactObject->country = $filteredAddress[4];
                        $contactObject->phone = $filteredAddress[5];
                        $contactObject->email = $filteredAddress[6];
                    }
                    
                    if (sizeof($filteredAddress) === 8) {
                        $contactObject->name = $filteredAddress[0];
                        $contactObject->org = $filteredAddress[2];
                        $contactObject->address = $filteredAddress[3];
                        $contactObject->city = $filteredAddress[4];
                        $contactObject->country = $filteredAddress[5];
                        $contactObject->phone = $filteredAddress[6];
                        $contactObject->email = $filteredAddress[7];
                    }
                    
                    $filteredAddress = array();
                }
            }
        }
    }
}