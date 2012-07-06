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
 * Template for Gtld_1api
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Gtld_1api extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/created-date:(?>[\x20\t]*)(.*?)(?=owner-organization)/is', 
            2 => '/owner-organization:(?>[\x20\t]*)(.*?)(?=admin-organization)/is', 
            3 => '/admin-organization:(?>[\x20\t]*)(.*?)(?=tech-organization)/is', 
            4 => '/tech-organization:(?>[\x20\t]*)(.*?)(?=billing-organization)/is', 
            5 => '/billing-organization:(?>[\x20\t]*)(.*?)(?=nameserver)/is', 
            6 => '/nameserver:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^created-date:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/^updated-date:(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/^registration-expiration-date:(?>[\x20\t]*)(.+)$/im' => 'expires'), 
            2 => array(
                    '/^owner-organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization', 
                    '/^owner-name:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/^owner-street:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address', 
                    '/^owner-city:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:city', 
                    '/^owner-state:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:state', 
                    '/^owner-zip:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:zipcode', 
                    '/^owner-country:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:country', 
                    '/^owner-phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:phone', 
                    '/^owner-fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:fax', 
                    '/^owner-email:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:email'), 
            3 => array(
                    '/^admin-organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:organization', 
                    '/^admin-name:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/^admin-street:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:address', 
                    '/^admin-city:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:city', 
                    '/^admin-state:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:state', 
                    '/^admin-zip:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:zipcode', 
                    '/^admin-country:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:country', 
                    '/^admin-phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone', 
                    '/^admin-fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:fax', 
                    '/^admin-email:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:email'), 
            4 => array('/^tech-organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:organization', 
                    '/^tech-name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/^tech-street:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:address', 
                    '/^tech-city:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:city', 
                    '/^tech-state:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:state', 
                    '/^tech-zip:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:zipcode', 
                    '/^tech-country:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:country', 
                    '/^tech-phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/^tech-fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:fax', 
                    '/^tech-email:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email'), 
            5 => array(
                    '/^billing-organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:organization', 
                    '/^billing-name:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:name', 
                    '/^billing-street:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:address', 
                    '/^billing-city:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:city', 
                    '/^billing-state:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:state', 
                    '/^billing-zip:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:zipcode', 
                    '/^billing-country:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:country', 
                    '/^billing-phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:phone', 
                    '/^billing-fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:fax', 
                    '/^billing-email:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:email'), 
            6 => array('/^nameserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver'));
}