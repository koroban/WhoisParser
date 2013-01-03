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
 * Template for .KR
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Kr extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(
            1 => '/Registrant(?>[\x20\t]*):(?>[\x20\t]*)(.*?)(?=Administrative Contact)/is', 
            2 => '/Administrative Contact\(AC\)(?>[\x20\t]*):(?>[\x20\t]*)(.*?)(?=Registered Date)/is', 
            3 => '/Registered Date(?>[\x20\t]*):(?>[\x20\t]*)(.*?)(?=Primary Name Server)/is', 
            4 => '/Primary Name Server(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^Registrant(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/^Registrant Address(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address', 
                    '/^Registrant Zip Code(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:zipcode'), 
            2 => array(
                    '/^Administrative Contact\(AC\)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/^AC E-Mail(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:email', 
                    '/^AC Phone Number(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone'), 
            3 => array('/^Registered Date(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/^Last updated Date(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/^Expiration Date(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/^Publishes(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'status', 
                    '/^Authorized Agency(?>[\x20\t]*):(?>[\x20\t]*)(.+)\(.+\)$/im' => 'registrar:name', 
                    '/^Authorized Agency(?>[\x20\t]*):(?>[\x20\t]*).+\((.+)\)$/im' => 'registrar:url'), 
            4 => array('/(?>[\x20\t]*)Host Name(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'nameserver'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/Above domain name is not registered/i';

    /**
     * After parsing ...
     *
     * Fix address dates
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        $ResultSet->created = str_replace('. ', '-', $ResultSet->created);
        $ResultSet->changed = str_replace('. ', '-', $ResultSet->changed);
        $ResultSet->expires = str_replace('. ', '-', $ResultSet->expires);
    }
}