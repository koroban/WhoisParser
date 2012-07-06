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
 * Template for Gtld_psiusa
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Gtld_psiusa extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/^domain:(?>[\x20\t]*)(.+)[\n]{2}$/ims', 
            2 => '/\[(admin|owner|tech|zone)-c\]\x20handle:(?>[\x20\t]*)(.*?)[\n]{2}/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^status:(?>[\x20\t]*)(.+)$/im' => 'status', 
                    '/^owner-c:(?>[\x20\t]*)LULU-(.+)$/im' => 'network:contacts:owner', 
                    '/^admin-c:(?>[\x20\t]*)LULU-(.+)$/im' => 'network:contacts:admin', 
                    '/^tech-c:(?>[\x20\t]*)LULU-(.+)$/im' => 'network:contacts:tech', 
                    '/^zone-c:(?>[\x20\t]*)LULU-(.+)$/im' => 'network:contacts:zone', 
                    '/^nserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver', 
                    '/^created:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/^expire:(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/^changed:(?>[\x20\t]*)(.+)$/im' => 'changed'), 
            2 => array(
                    '/^\[(owner|admin|tech|zone)-c\]\x20handle:(?>[\x20\t]*)(.+)$/im' => 'contacts:handle', 
                    '/^\[(owner|admin|tech|zone)-c\]\x20type:(?>[\x20\t]*)(.+)$/im' => 'contacts:type', 
                    '/^\[(owner|admin|tech|zone)-c\]\x20title:(?>[\x20\t]*)(.+)$/im' => 'contacts:title', 
                    '/^\[(owner|admin|tech|zone)-c\]\x20org:(?>[\x20\t]*)(.+)$/im' => 'contacts:organization', 
                    '/^\[(owner|admin|tech|zone)-c\]\x20(f|l)name:(?>[\x20\t]*)(.+)$/im' => 'contacts:name', 
                    '/^\[(owner|admin|tech|zone)-c\]\x20address:(?>[\x20\t]*)(.+)$/im' => 'contacts:address', 
                    '/^\[(owner|admin|tech|zone)-c\]\x20city:(?>[\x20\t]*)(.+)$/im' => 'contacts:city', 
                    '/^\[(owner|admin|tech|zone)-c\]\x20state:(?>[\x20\t]*)(.+)$/im' => 'contacts:state', 
                    '/^\[(owner|admin|tech|zone)-c\]\x20pcode:(?>[\x20\t]*)(.+)$/im' => 'contacts:zipcode', 
                    '/^\[(owner|admin|tech|zone)-c\]\x20country:(?>[\x20\t]*)(.+)$/im' => 'contacts:country', 
                    '/^\[(owner|admin|tech|zone)-c\]\x20phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:phone', 
                    '/^\[(owner|admin|tech|zone)-c\]\x20fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:fax', 
                    '/^\[(owner|admin|tech|zone)-c\]\x20email:(?>[\x20\t]*)(.+)$/im' => 'contacts:email', 
                    '/^\[(owner|admin|tech|zone)-c\]\x20updated:(?>[\x20\t]*)(.+)$/im' => 'contacts:changed'));
}