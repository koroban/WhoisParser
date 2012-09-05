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
 * Template for Gtld_gandi
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Gtld_gandi extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/owner-c:(.*?)(?=admin-c)/is', 
            2 => '/admin-c:(.*?)(?=tech-c)/is', 3 => '/tech-c:(?>[\x20\t]*)(.*?)(?=bill-c)/is', 
            4 => '/bill-c:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array(
                    '/^(?>[\x20\t]*)nic-hdl(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:handle', 
                    '/^(?>[\x20\t]*)organisation(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization', 
                    '/^(?>[\x20\t]*)person(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/^(?>[\x20\t]*)address(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address', 
                    '/^(?>[\x20\t]*)city(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:city', 
                    '/^(?>[\x20\t]*)zipcode(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:zipcode', 
                    '/^(?>[\x20\t]*)country(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:country', 
                    '/^(?>[\x20\t]*)phone(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:phone', 
                    '/^(?>[\x20\t]*)fax(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:fax', 
                    '/^(?>[\x20\t]*)email(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:email', 
                    '/^(?>[\x20\t]*)lastupdated(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:changed'), 
            2 => array(
                    '/^(?>[\x20\t]*)nic-hdl(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:handle', 
                    '/^(?>[\x20\t]*)organisation(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:organization', 
                    '/^(?>[\x20\t]*)person(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/^(?>[\x20\t]*)address(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:address', 
                    '/^(?>[\x20\t]*)city(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:city', 
                    '/^(?>[\x20\t]*)zipcode(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:zipcode', 
                    '/^(?>[\x20\t]*)country(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:country', 
                    '/^(?>[\x20\t]*)phone(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone', 
                    '/^(?>[\x20\t]*)fax(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:fax', 
                    '/^(?>[\x20\t]*)email(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:email', 
                    '/^(?>[\x20\t]*)lastupdated(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:changed'), 
            3 => array(
                    '/^(?>[\x20\t]*)nic-hdl(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:handle', 
                    '/^(?>[\x20\t]*)organisation(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:organization', 
                    '/^(?>[\x20\t]*)person(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/^(?>[\x20\t]*)address(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:address', 
                    '/^(?>[\x20\t]*)city(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:city', 
                    '/^(?>[\x20\t]*)zipcode(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:zipcode', 
                    '/^(?>[\x20\t]*)country(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:country', 
                    '/^(?>[\x20\t]*)phone(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/^(?>[\x20\t]*)fax(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:fax', 
                    '/^(?>[\x20\t]*)email(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email', 
                    '/^(?>[\x20\t]*)lastupdated(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:changed'), 
            4 => array(
                    '/^(?>[\x20\t]*)nic-hdl(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:handle', 
                    '/^(?>[\x20\t]*)organisation(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:organization', 
                    '/^(?>[\x20\t]*)person(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:name', 
                    '/^(?>[\x20\t]*)address(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:address', 
                    '/^(?>[\x20\t]*)city(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:city', 
                    '/^(?>[\x20\t]*)zipcode(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:zipcode', 
                    '/^(?>[\x20\t]*)country(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:country', 
                    '/^(?>[\x20\t]*)phone(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:phone', 
                    '/^(?>[\x20\t]*)fax(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:fax', 
                    '/^(?>[\x20\t]*)email(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:email', 
                    '/^(?>[\x20\t]*)lastupdated(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:changed'));
}