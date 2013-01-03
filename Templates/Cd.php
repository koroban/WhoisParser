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
 * Template for .CD
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Cd extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Registrar:(?>[\x20\t]*)(.*?)(?=Owner\/Main Contact:)/is', 
            2 => '/Owner\/Main Contact:(?>[\x20\t]*)(.*?)(?=Administrative Contact:)/is', 
            3 => '/Administrative Contact:(?>[\x20\t]*)(.*?)(?=Technical Contact)/is', 
            4 => '/Technical Contact:(?>[\x20\t]*)(.*?)(?=Billing Contact)/is', 
            5 => '/Billing Contact:(?>[\x20\t]*)(.*?)(?=Name Servers)/is', 
            6 => '/Name Servers:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/Registrar:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/Creation Date:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/Expiration Date:(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/Domain Status:(?>[\x20\t]*)(.+)$/im' => 'status'), 
            2 => array('/Name:(?>[\x20\t]*)(.+)\([0-9a-z\-]+\)/im' => 'contacts:owner:name', 
                    '/Name:(?>[\x20\t]*).+\(([0-9a-z\-]+)\)/im' => 'contacts:owner:handle', 
                    '/Registered Address(line[0-9]):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address', 
                    '/Registered State:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:state', 
                    '/Registered Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:country', 
                    '/Registered Postalcode:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:zipcode', 
                    '/Telephone:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:phone', 
                    '/Facsimile:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:fax', 
                    '/EMAIL:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:email'), 
            3 => array('/Name:(?>[\x20\t]*)(.+)\([0-9a-z\-]+\)/im' => 'contacts:admin:name', 
                    '/Name:(?>[\x20\t]*).+\(([0-9a-z\-]+)\)/im' => 'contacts:admin:handle', 
                    '/Registered Address(line[0-9]):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:address', 
                    '/Registered State:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:state', 
                    '/Registered Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:country', 
                    '/Registered Postalcode:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:zipcode', 
                    '/Telephone:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone', 
                    '/Facsimile:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:fax', 
                    '/EMAIL:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:email'), 
            4 => array('/Name:(?>[\x20\t]*)(.+)\([0-9a-z\-]+\)/im' => 'contacts:tech:name', 
                    '/Name:(?>[\x20\t]*).+\(([0-9a-z\-]+)\)/im' => 'contacts:tech:handle', 
                    '/Registered Address(line[0-9]):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:address', 
                    '/Registered State:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:state', 
                    '/Registered Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:country', 
                    '/Registered Postalcode:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:zipcode', 
                    '/Telephone:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/Facsimile:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:fax', 
                    '/EMAIL:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email'), 
            5 => array('/Name:(?>[\x20\t]*)(.+)\([0-9a-z\-]+\)/im' => 'contacts:billing:name', 
                    '/Name:(?>[\x20\t]*).+\(([0-9a-z\-]+)\)/im' => 'contacts:billing:handle', 
                    '/Registered Address(line[0-9]):(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:address', 
                    '/Registered State:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:state', 
                    '/Registered Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:country', 
                    '/Registered Postalcode:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:zipcode', 
                    '/Telephone:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:phone', 
                    '/Facsimile:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:fax', 
                    '/EMAIL:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:email'), 
            6 => array('/Name Servers:[\n](?>[\x20\t]*)(.+)$/is' => 'nameserver'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/Domain Not Found/i';

    /**
     * After parsing ...
     *
     * Fix nameserver in WHOIS output
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        $filteredNameserver = array();
        
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