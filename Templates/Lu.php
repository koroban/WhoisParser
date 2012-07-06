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
 * Template for .LU
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Lu extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/domainname:(?>[\x20\t]*)(.*?)(?=org-name:)/is', 
            2 => '/org-name:(?>[\x20\t]*)(.*?)(?=adm-name)/is', 
            3 => '/adm-name:(?>[\x20\t]*)(.*?)(?=tec-name)/is', 
            4 => '/tec-name:(?>[\x20\t]*)(.*?)(?=registrar-name)/is', 
            5 => '/registrar-name:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^nserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver', 
                    '/^registered:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/^domaintype:(?>[\x20\t]*)(.+)$/im' => 'status'), 
            2 => array('/^org-name:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/^org-address:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address', 
                    '/^org-zipcode:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:zipcode', 
                    '/^org-city:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:city', 
                    '/^org-country:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:country', 
                    '/^org-email:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:email'), 
            3 => array('/^adm-name:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/^adm-address:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:address', 
                    '/^adm-zipcode:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:zipcode', 
                    '/^adm-city:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:city', 
                    '/^adm-country:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:country', 
                    '/^adm-email:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:email'), 
            4 => array('/^tec-name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/^tec-address:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:address', 
                    '/^tec-zipcode:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:zipcode', 
                    '/^tec-city:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:city', 
                    '/^tec-country:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:country', 
                    '/^tec-email:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email'), 
            5 => array('/^registrar-name:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/^registrar-email:(?>[\x20\t]*)(.+)$/im' => 'registrar:email', 
                    '/^registrar-url:(?>[\x20\t]*)(.+)$/im' => 'registrar:url'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No such domain/i';
}