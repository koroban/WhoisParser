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
 * Template for .MX
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Mx extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Domain Name:(?>[\x20\t]*)(.*?)(?=Registrant)/is', 
            2 => '/Registrant:(?>[\x20\t]*)(.*?)(?=Administrative Contact)/is', 
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
            1 => array('/^Created On:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/^Expiration Date:(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/^Last Updated On:(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/^Registrar:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/^URL:(?>[\x20\t]*)(.+)$/im' => 'registrar:url'), 
            2 => array('/(?>[\x20\t]*)Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/(?>[\x20\t]*)City:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:city', 
                    '/(?>[\x20\t]*)State:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:state', 
                    '/(?>[\x20\t]*)Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:country'), 
            3 => array('/(?>[\x20\t]*)Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/(?>[\x20\t]*)City:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:city', 
                    '/(?>[\x20\t]*)State:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:state', 
                    '/(?>[\x20\t]*)Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:country'), 
            4 => array('/(?>[\x20\t]*)Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/(?>[\x20\t]*)City:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:city', 
                    '/(?>[\x20\t]*)State:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:state', 
                    '/(?>[\x20\t]*)Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:country'), 
            5 => array('/(?>[\x20\t]*)Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:name', 
                    '/(?>[\x20\t]*)City:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:city', 
                    '/(?>[\x20\t]*)State:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:state', 
                    '/(?>[\x20\t]*)Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:country'), 
            6 => array('/(?>[\x20\t]*)DNS:(?>[\x20\t]*)(.+)$/im' => 'nameserver'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/Object_Not_Found/i';
}