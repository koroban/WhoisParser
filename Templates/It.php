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
 * Template for .IT
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_It extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/(domain):[\s]*(.*?)[\r\n]{2}/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^status:[\s]*(.+)$/im' => 'status', '/^created:[\s]*(.+)$/im' => 'created', 
                    '/^lastUpdate:[\s]*(.+)$/im' => 'changed', 
                    '/^Last Update:[\s]*(.+)$/im' => 'changed', 
                    '/^expire:[\s]*(.+)$/im' => 'expires', 
                    '/^Expire Date:[\s]*(.+)$/im' => 'expires', 
                    '/^mnt-by:[\s]*(.+)$/im' => 'registrar:id', 
                    '/^registrant:[\s]*(.+)$/im' => 'network:contacts:owner', 
                    '/^admin:[\s]*(.+)$/im' => 'network:contacts:admin', 
                    '/^tech:[\s]*(.+)$/im' => 'network:contacts:tech', 
                    '/^nserver:[\s]*(.+)$/im' => 'nameserver'), 
            
            2 => array('/^[\s]*contactid:[\s]*(.+)$/im' => 'contact:handle', 
                    '/^[\s]*contacttype:[\s]*(.+)$/im' => 'contact:type', 
                    '/^[\s]*regcode:[\s]*(.+)$/im' => 'contact:regcode', 
                    '/^[\s]*entitytype:[\s]*(.+)$/im' => 'contact:entity', 
                    '/^[\s]*name:[\s]*(.+)$/im' => 'contact:name', 
                    '/^[\s]*org:[\s]*(.+)$/im' => 'contact:organization', 
                    '/^[\s]*postalcode:[\s]*(.+)$/im' => 'contact:zipcode', 
                    '/^[\s]*city:[\s]*(.+)$/im' => 'contact:city', 
                    '/^[\s]*stateOrProvince:[\s]*(.+)$/im' => 'contact:state', 
                    '/^[\s]*countryCode:[\s]*(.+)$/im' => 'contact:country', 
                    '/^[\s]*voice:[\s]*(.+)$/im' => 'contact:phone', 
                    '/^[\s]*fax:[\s]*(.+)$/im' => 'contact:fax', 
                    '/^[\s]*email:[\s]*(.+)$/im' => 'contact:email', 
                    '/^[\s]*created:[\s]*(.+)$/im' => 'contact:created', 
                    '/^[\s]*last update:[\s]*(.+)$/im' => 'contact:changed'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/(Status:[\s]*AVAILABLE)[\r\n]/i';
}