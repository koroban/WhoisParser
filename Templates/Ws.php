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
 * Template for .WS
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Ws extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Registrar Name:(?>[\x20\t]*)(.*?)(?=Domain Created)/is', 
            2 => '/Domain Created:(?>[\x20\t]*)(.*?)(?=Current Nameservers)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/(?>[\x20\t]*)Registrar Name:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/(?>[\x20\t]*)Registrar Email:(?>[\x20\t]*)(.+)$/im' => 'registrar:email', 
                    '/(?>[\x20\t]*)Registrar Whois:(?>[\x20\t]*)(.+)$/im' => 'whoisserver'), 
            
            2 => array('/(?>[\x20\t]*)Domain Created:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/(?>[\x20\t]*)Domain Last Updated:(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/(?>[\x20\t]*)Domain Currently Expires:(?>[\x20\t]*)(.+)$/im' => 'expires'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No match for /i';

    /**
     * After parsing ...
     * 
     * Verisign is a thin registry, therefore they only provide us some details and the
     * real whois server of the registrar for the given domain name. Therefore we have
     * to restart the process with the real whois server.
     * 
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        $Config = $WhoisParser->getConfig();
        
        // check if registrar name is set, if not then there was an error while
        // parsing
        if (! isset($ResultSet->registrar->name)) {
            return;
        }
        
        $newConfig = $Config->get($ResultSet->whoisserver);
        $newConfig['server'] = $ResultSet->whoisserver;
        
        $Config->setCurrent($newConfig);
        $WhoisParser->call();
    }
}