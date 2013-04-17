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
 * Template for .VE
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Ve extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Titular:(?>[\x20\t]*)(.*?)(?=Nombre de Dominio\:)/is', 
            2 => '/Contacto Administrativo:(?>[\x20\t]*)(.*?)(?=Contacto Tecnico)/is', 
            3 => '/Contacto Tecnico:(?>[\x20\t]*)(.*?)(?=Contacto de Cobranza)/is', 
            4 => '/Contacto de Cobranza:(?>[\x20\t]*)(.*?)(?=(Fecha de Vencimiento|Ultima Actualizacion))/is', 
            5 => '/(Fecha de Vencimiento|Ultima Actualizacion):(?>[\x20\t]*)(.*?)(?=Servidor\(es\) de Nombres de Dominio)/is', 
            6 => '/Servidor\(es\) de Nombres de Dominio:(?>[\x20\t]*)(.*?)(?=NIC-Venezuela)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/Titular:(?>[\x20\t\n]*)(.*?)$/is' => 'contacts:owner:address'), 
            2 => array(
                    '/Contacto Administrativo:(?>[\x20\t\n]*)(.*?)$/is' => 'contacts:admin:address'), 
            3 => array('/Contacto Tecnico:(?>[\x20\t\n]*)(.*?)$/is' => 'contacts:tech:address'), 
            4 => array(
                    '/Contacto de Cobranza:(?>[\x20\t\n]*)(.*?)$/is' => 'contacts:billing:address'), 
            5 => array('/Fecha de Vencimiento:(?>[\x20\t]*)(.*?)$/im' => 'expires', 
                    '/Ultima Actualizacion:(?>[\x20\t]*)(.*?)$/im' => 'changed', 
                    '/Fecha de Creacion:(?>[\x20\t]*)(.*?)$/im' => 'created', 
                    '/Estatus del dominio:(?>[\x20\t]*)(.*?)$/im' => 'status'), 
            6 => array(
                    '/Servidor\(es\) de Nombres de Dominio:(?>[\x20\t\n]*)(.*?)\n\n/is' => 'nameserver'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No match for/i';

    /**
     * After parsing do something
     *
     * Fix contacts and nameservers
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        $filteredAddress = array();
        $filteredNameserver = array();
        
        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                if (! is_array($contactObject->address)) {
                    $explodedAddress = explode("\n", trim($contactObject->address));
                    
                    foreach ($explodedAddress as $key => $line) {
                        $filteredAddress[] = trim($line);
                    }
                    
                    preg_match('/(.*?)(?>[\x20\t]*)\((.*?)\)(?>[\x20\t]*)(.*?)$/im', $filteredAddress[0], $matches);
                    
                    $contactObject->name = $matches[1];
                    $contactObject->handle = $matches[2];
                    $contactObject->email = $matches[3];
                    $contactObject->organization = $filteredAddress[1];
                    
                    if (sizeof($filteredAddress) === 5) {
                        $contactObject->address = array($filteredAddress[2], $filteredAddress[3]);
                    } else {
                        $contactObject->address = $filteredAddress[3];
                    }
                    
                    if (stripos(end($filteredAddress), 'fax')) {
                        $matches = explode(' (FAX) ', end($filteredAddress));
                        $contactObject->phone = $matches[0];
                        $contactObject->fax = $matches[1];
                    } else {
                        $contactObject->phone = end($filteredAddress);
                    }
                    
                    $filteredAddress = array();
                }
            }
        }
        
        if (isset($ResultSet->nameserver) && $ResultSet->nameserver != '' &&
                 ! is_array($ResultSet->nameserver)) {
            $explodedNameserver = explode("\n", $ResultSet->nameserver);
            foreach ($explodedNameserver as $key => $line) {
                if (trim($line) != '') {
                    $filteredNameserver[] = str_replace('- ', '', trim($line));
                }
            }
            $ResultSet->nameserver = $filteredNameserver;
        }
    }
}