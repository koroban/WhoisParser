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
 * Template for CoCCA based TLDs like .BI, .CM, .EC, .FM, .GG, .JE, .PS
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Cocca extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/query:(.*?)(?=registrar name)/is', 
            2 => '/registrar name:(.*?)(?=registrant)/is', 
            3 => '/registrant:\n(.*?)(?=(admin|administrative) contact|$)/is', 
            4 => '/(admin|administrative) contact:\n(.*?)(?=technical contact|$)/is', 
            5 => '/technical contact:\n(.*?)(?=billing contact)/is', 
            6 => '/billing contact:\n(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/\n(?>[\x20\t]+)(.+)$/im' => 'nameserver', 
                    '/status:(?>[\x20\t]*)(.+)$/im' => 'status', 
                    '/created:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/modified:(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/expires:(?>[\x20\t]*)(.+)$/im' => 'expires'), 
            
            2 => array('/registrar name:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/registration url:(?>[\x20\t]*)(.+)$/im' => 'registrar:url', 
                    '/customer service contacts:(?>[\x20\t]*)(.+)$/im' => 'registrar:email', 
                    '/customer service email:(?>[\x20\t]*)(.+)$/im' => 'registrar:email'), 
            
            3 => array('/name:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/(company|organisation):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization', 
                    '/email( address)?:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:email', 
                    '/\n(?>[\x20\t]+)(.+)$/im' => 'contacts:owner:address', 
                    '/phone number:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:phone', 
                    '/city:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:city', 
                    '/country:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:country', 
                    '/postal code:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:zipcode', 
                    '/fax( number)?:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:fax'), 
            
            4 => array('/name:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/(company|organisation):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:organization', 
                    '/email( address)?:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:email', 
                    '/\n(?>[\x20\t]+)(.+)$/im' => 'contacts:admin:address', 
                    '/phone number:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone', 
                    '/city:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:city', 
                    '/country:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:country', 
                    '/postal code:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:zipcode', 
                    '/fax( number)?:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:fax'), 
            
            5 => array('/name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/(company|organisation):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:organization', 
                    '/email( address)?:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email', 
                    '/\n(?>[\x20\t]+)(.+)$/im' => 'contacts:tech:address', 
                    '/phone number:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/city:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:city', 
                    '/country:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:country', 
                    '/postal code:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:zipcode', 
                    '/fax( number)?:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:fax'), 
            
            6 => array('/name:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:name', 
                    '/email address:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:email', 
                    '/\n(?>[\x20\t]+)(.+)$/im' => 'contacts:billing:address', 
                    '/phone number:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:phone', 
                    '/fax number:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:fax'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/(Status: Not Registered|Domain does not exist)/i';

    /**
     * After parsing ...
     * 
     * Fix email addresses in WHOIS output
     * 
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                $contactObject->email = str_ireplace(array(' at ', ' dot '), array('@', '.'), $contactObject->email);
            }
        }
        
        if (isset($ResultSet->registrar->email) && $ResultSet->registrar->email != '') {
            $ResultSet->registrar->email = str_ireplace(array(' at ', ' dot '), array('@', '.'), $ResultSet->registrar->email);
        }
    }
}