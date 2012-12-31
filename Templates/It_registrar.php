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
 * Template for .IT Registrar WHOIS
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_It_registrar extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/domain:(?>[\x20\t]*)(.*?)(?=name)/is', 
            2 => '/name:(?>[\x20\t]*)(.*?)(?=name|$)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^status:(?>[\x20\t]*)(.+)$/im' => 'status', 
                    '/^created:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/^lastUpdate:(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/^expire:(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/^mnt-by:(?>[\x20\t]*)(.+)$/im' => 'registrar:id', 
                    '/^registrant:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:owner', 
                    '/^admin:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:admin', 
                    '/^tech:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:tech', 
                    '/^nserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver'), 
            
            2 => array('/contactid:(?>[\x20\t]*)(.+)$/im' => 'contacts:handle', 
                    '/contacttype:(?>[\x20\t]*)(.+)$/im' => 'contacts:type', 
                    '/regCode:(?>[\x20\t]*)(.+)$/im' => 'contacts:regcode', 
                    '/entityType:(?>[\x20\t]*)(.+)$/im' => 'contacts:entitytype', 
                    '/consentForPublishing:(?>[\x20\t]*)(.+)$/im' => 'contacts:consentforpublishing', 
                    '/nationalityCode:(?>[\x20\t]*)(.+)$/im' => 'contacts:nationalitycode', 
                    '/name:(?>[\x20\t]*)(.+)$/im' => 'contacts:name', 
                    '/org:(?>[\x20\t]*)(.+)$/im' => 'contacts:organization', 
                    '/street:(?>[\x20\t]*)(.+)$/im' => 'contacts:address', 
                    '/city:(?>[\x20\t]*)(.+)$/im' => 'contacts:city', 
                    '/postalcode:(?>[\x20\t]*)(.+)$/im' => 'contacts:zipcode', 
                    '/stateOrProvince:(?>[\x20\t]*)(.+)$/im' => 'contacts:state', 
                    '/countryCode:(?>[\x20\t]*)(.+)$/im' => 'contacts:country', 
                    '/voice:(?>[\x20\t]*)(.+)$/im' => 'contacts:phone', 
                    '/fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:fax', 
                    '/email:(?>[\x20\t]*)(.+)$/im' => 'contacts:email', 
                    '/created:(?>[\x20\t]*)(.+)$/im' => 'contacts:created', 
                    '/last update:(?>[\x20\t]*)(.+)$/im' => 'contacts:changed'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/(Status:[\s]*AVAILABLE)[\r\n]/i';
}