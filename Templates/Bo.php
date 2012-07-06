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
 * Template for .BO
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Bo extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/TITULAR:(?>[\x20\t]*)(.*?)(?=CONTACTO ADMINISTRATIVO)/is', 
            2 => '/CONTACTO ADMINISTRATIVO:(?>[\x20\t]*)(.*?)(?=CONTACTO TECNICO)/is', 
            3 => '/CONTACTO TECNICO:(?>[\x20\t]*)(.*?)(?=CONTACTO FINANCIERO)/is', 
            4 => '/CONTACTO FINANCIERO:(?>[\x20\t]*)(.*?)(?=Fecha de registro)/is', 
            5 => '/Fecha de registro:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^Organizacion:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization', 
                    '/^Nombre:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/^Direccion:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address', 
                    '/^Ciudad:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:city', 
                    '/^Pais:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:country', 
                    '/^Telefono:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:phone', 
                    '/^Email:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:email'), 
            2 => array('/^Organizacion:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:organization', 
                    '/^Nombre:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/^Direccion:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:address', 
                    '/^Ciudad:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:city', 
                    '/^Pais:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:country', 
                    '/^Telefono:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone', 
                    '/^Email:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:email'), 
            3 => array('/^Organizacion:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:organization', 
                    '/^Nombre:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/^Direccion:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:address', 
                    '/^Ciudad:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:city', 
                    '/^Pais:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:country', 
                    '/^Telefono:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/^Email:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email'), 
            4 => array('/^Organizacion:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:organization', 
                    '/^Nombre:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:name', 
                    '/^Direccion:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:address', 
                    '/^Ciudad:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:city', 
                    '/^Pais:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:country', 
                    '/^Telefono:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:phone', 
                    '/^Email:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:email'), 
            5 => array('/^Fecha de registro:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/^Fecha de vencimiento:(?>[\x20\t]*)(.+)$/im' => 'expires'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/(Dominio)/i';

    /**
     * After parsing ...
     *
     * Fix email and available in whois output
     *
     * @param  object $whoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        if (isset($ResultSet->contacts->owner)) {
            $ResultSet->registered = true;
        }
        
        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                if ($contactObject->email != '') {
                    $contactObject->email = str_replace(' en ', '@', $contactObject->email);
                }
            }
        }
    }
}