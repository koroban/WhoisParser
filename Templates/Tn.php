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
 * Template for .TN
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Tn extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Domain(?>[\x20\t]*):(?>[\x20\t]*)(.*?)(?=Owner Name)/is', 
            2 => '/Owner Name(?>[\x20\t]*):(?>[\x20\t]*)(.*?)(?=Admin\. Name)/is', 
            3 => '/Admin\. Name(?>[\x20\t]*):(?>[\x20\t]*)(.*?)(?=Tech\. Name)/is', 
            4 => '/Tech\. Name(?>[\x20\t]*):(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/Acivated(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/Registrar(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/NameServers(?>[\x20\t]*):(?>[\x20\t]*)(.*?)\. \[/im' => 'nameserver', 
                    '/NameServers(?>[\x20\t]*):(?>[\x20\t]*).*? \[(.*?)\]$/im' => 'ips'), 
            2 => array('/Owner Name(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/Owner Address(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address', 
                    '/Owner Updated(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:changed', 
                    '/Owner Created(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:created', 
                    '/Owner Tel(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:phone', 
                    '/Owner Fax(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:fax', 
                    '/Owner Email(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:email'), 
            3 => array('/Admin\. Name(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/Admin\. Address(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:address', 
                    '/Admin\. Updated(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:changed', 
                    '/Admin\. Created(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:created', 
                    '/Admin\. Tel(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone', 
                    '/Admin\. Fax(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:fax', 
                    '/Admin\. Email(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:email'), 
            4 => array('/Tech\. Name(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/Tech\. Address(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:address', 
                    '/Tech\. Updated(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:changed', 
                    '/Tech\. Created(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:created', 
                    '/Tech\. Tel(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/Tech\. Fax(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:fax', 
                    '/Tech\. Email(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/not found/i';
}