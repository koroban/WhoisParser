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
    protected $blocks = array(1 => '/registrar:(?>[\x20\t]*)(.*?)(?=owner\/main Contact)/is', 
            2 => '/owner\/main contact:(?>[\x20\t]*)(.*?)(?=administrative contact)/is', 
            3 => '/administrative contact:(?>[\x20\t]*)(.*?)(?=technical contact)/is', 
            4 => '/technical contact:(?>[\x20\t]*)(.*?)(?=billing contact)/is', 
            5 => '/billing contact:(?>[\x20\t]*)(.*?)(?=name servers)/is', 
            6 => '/name servers:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/registrar:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/creation date:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/expiration date:(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/domain status:(?>[\x20\t]*)(.+)$/im' => 'status'), 
            2 => array('/name:(?>[\x20\t]*)(.+)\([0-9a-z\-]+\)/im' => 'contacts:owner:name', 
                    '/name:(?>[\x20\t]*).+\(([0-9a-z\-]+)\)/im' => 'contacts:owner:handle', 
                    '/registered address\(line[0-9]\):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address', 
                    '/registered state:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:state', 
                    '/registered country:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:country', 
                    '/registered postalcode:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:zipcode', 
                    '/telephone:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:phone', 
                    '/facsimile:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:fax', 
                    '/email:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:email'), 
            3 => array('/name:(?>[\x20\t]*)(.+)\([0-9a-z\-]+\)/im' => 'contacts:admin:name', 
                    '/name:(?>[\x20\t]*).+\(([0-9a-z\-]+)\)/im' => 'contacts:admin:handle', 
                    '/registered address\(line[0-9]\):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:address', 
                    '/registered state:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:state', 
                    '/registered country:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:country', 
                    '/registered postalcode:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:zipcode', 
                    '/telephone:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone', 
                    '/facsimile:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:fax', 
                    '/email:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:email'), 
            4 => array('/name:(?>[\x20\t]*)(.+)\([0-9a-z\-]+\)/im' => 'contacts:tech:name', 
                    '/name:(?>[\x20\t]*).+\(([0-9a-z\-]+)\)/im' => 'contacts:tech:handle', 
                    '/registered address\(line[0-9]\):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:address', 
                    '/registered state:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:state', 
                    '/registered country:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:country', 
                    '/registered postalcode:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:zipcode', 
                    '/telephone:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/facsimile:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:fax', 
                    '/email:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email'), 
            5 => array('/name:(?>[\x20\t]*)(.+)\([0-9a-z\-]+\)/im' => 'contacts:billing:name', 
                    '/name:(?>[\x20\t]*).+\(([0-9a-z\-]+)\)/im' => 'contacts:billing:handle', 
                    '/registered address\(line[0-9]\):(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:address', 
                    '/registered state:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:state', 
                    '/registered country:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:country', 
                    '/registered postalcode:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:zipcode', 
                    '/telephone:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:phone', 
                    '/facsimile:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:fax', 
                    '/email:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:email'), 
            6 => array('/\n(?>[\x20\t]+)(.+)$/im' => 'nameserver'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/domain not found/i';
}