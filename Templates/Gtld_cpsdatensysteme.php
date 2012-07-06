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
 * Template for Gtld_cpsdatensysteme
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Gtld_cpsdatensysteme extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(
            1 => '/\[domain\]\x20domainname:(?>[\x20\t]*)(.*?)(?=\[owner-c\] contact-id)/is', 
            2 => '/\[(admin|owner|tech)-c\]\x20contact-id:(?>[\x20\t]*)(.*?)[\r\n]{3}/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^\[domain\] status:(?>[\x20\t]*)(.+)$/im' => 'status', 
                    '/^\[domain\] owner-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:owner', 
                    '/^\[domain\] admin-c:(?>[\x20\t]*)LULU-(.+)$/im' => 'network:contacts:admin', 
                    '/^\[domain\] tech-c:(?>[\x20\t]*)LULU-(.+)$/im' => 'network:contacts:tech', 
                    '/^\[domain\] nserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver', 
                    '/^\[domain\] created:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/^\[domain\] expire:(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/^\[domain\] modified:(?>[\x20\t]*)(.+)$/im' => 'changed'), 
            2 => array(
                    '/^\[(owner|admin|tech)-c\]\x20contact-id:(?>[\x20\t]*)(.+)$/im' => 'contacts:handle', 
                    '/^\[(owner|admin|tech)-c\]\x20type:(?>[\x20\t]*)(.+)$/im' => 'contacts:type', 
                    '/^\[(owner|admin|tech)-c\]\x20title:(?>[\x20\t]*)(.+)$/im' => 'contacts:title', 
                    '/^\[(owner|admin|tech)-c\]\x20organisation:(?>[\x20\t]*)(.+)$/im' => 'contacts:organization', 
                    '/^\[(owner|admin|tech)-c\]\x20name:(?>[\x20\t]*)(.+)$/im' => 'contacts:name', 
                    '/^\[(owner|admin|tech)-c\]\x20street:(?>[\x20\t]*)(.+)$/im' => 'contacts:address', 
                    '/^\[(owner|admin|tech)-c\]\x20city:(?>[\x20\t]*)(.+)$/im' => 'contacts:city', 
                    '/^\[(owner|admin|tech)-c\]\x20state:(?>[\x20\t]*)(.+)$/im' => 'contacts:state', 
                    '/^\[(owner|admin|tech)-c\]\x20postal:(?>[\x20\t]*)(.+)$/im' => 'contacts:zipcode', 
                    '/^\[(owner|admin|tech)-c\]\x20country:(?>[\x20\t]*)(.+)$/im' => 'contacts:country', 
                    '/^\[(owner|admin|tech)-c\]\x20phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:phone', 
                    '/^\[(owner|admin|tech)-c\]\x20fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:fax', 
                    '/^\[(owner|admin|tech)-c\]\x20email:(?>[\x20\t]*)(.+)$/im' => 'contacts:email'));

    /**
     * After parsing do something
     *
     * Clear empty lines at nameservers
     *
     * @param  object $whoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        $filteredAddress = array();
        
        if (isset($ResultSet->nameserver) && $ResultSet->nameserver != '' &&
                 is_array($ResultSet->nameserver)) {
            foreach ($ResultSet->nameserver as $key => $line) {
                if (trim($line) != '') {
                    $filteredAddress[] = strtolower(trim($line));
                }
            }
            
            $ResultSet->nameserver = $filteredAddress;
            $filteredAddress = array();
        }
    }
}