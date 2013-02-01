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
 * Template for .PT
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Pt extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Nome de dom(?>[\x20\t]*)(.*?)(?=Titular)/is', 
            2 => '/Registrant(?>[\x20\t]*)(.*?)(?=Entidade Gestora)/is', 
            3 => '/Billing Contact(?>[\x20\t]*)(.*?)(?=Respons)/is', 
            4 => '/Tech Contact(?>[\x20\t]*)(.*?)(?=Nameserver Information)/is', 
            5 => '/Nameserver Information(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/Status:(?>[\x20\t]*)(.*?)$/im' => 'status', 
                    '/Creation Date \(dd\/mm\/yyyy\):(?>[\x20\t]*)(.*?)$/im' => 'created', 
                    '/Expiration Date \(dd\/mm\/yyyy\):(?>[\x20\t]*)(.*?)$/im' => 'expires'), 
            2 => array(
                    '/Registrant(?>[\x20\t\n]*)(.*?)\n(?>[\x20\t]*)Email:/is' => 'contacts:owner:address', 
                    '/Email:(?>[\x20\t]*)(.*?)$/im' => 'contacts:owner:email'), 
            3 => array('/Billing Contact(?>[\x20\t\n]*)(.*?)\n/is' => 'contacts:billing:name', 
                    '/Email:(?>[\x20\t]*)(.*?)$/im' => 'contacts:billing:email'), 
            4 => array('/Tech Contact(?>[\x20\t\n]*)(.*?)\n/is' => 'contacts:tech:name', 
                    '/Email:(?>[\x20\t]*)(.*?)$/im' => 'contacts:tech:email'), 
            5 => array(
                    '/Nameserver:(?>[\x20\t]*).*?(?>[\x20\t]*)NS(?>[\x20\t]*)(.*?).$/im' => 'nameserver'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/no match/i';

    /**
     * After parsing do something
     *
     * Fix owner contact
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        if (! is_array($ResultSet->contacts->owner[0]->address)) {
            $explodedAddress = explode("\n", trim($ResultSet->contacts->owner[0]->address));
            $ResultSet->contacts->owner[0]->organization = trim($explodedAddress[0]);
            $ResultSet->contacts->owner[0]->address = trim($explodedAddress[1]);
            $ResultSet->contacts->owner[0]->city = trim($explodedAddress[2]);
            $ResultSet->contacts->owner[0]->zipcode = trim($explodedAddress[3]);
        }
        
        if (strpos($ResultSet->contacts->owner[0]->email, ';')) {
            $ResultSet->contacts->owner[0]->email = explode(';', $ResultSet->contacts->owner[0]->email);
        }
    }
}