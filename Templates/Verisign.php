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
 * Template for Verisign
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Verisign extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Domain Name:(?>[\x20\t]*)(.*?)(?=>>>)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/(?>[\x20\t]*)whois server:(?>[\x20\t]*)(.+)$/im' => 'whoisserver', 
                    '/(?>[\x20\t]*)registrar:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/(?>[\x20\t]*)referral url:(?>[\x20\t]*)(.+)$/im' => 'registrar:url', 
                    '/(?>[\x20\t]*)creation date:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/(?>[\x20\t]*)expiration date:(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/(?>[\x20\t]*)updated date:(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/(?>[\x20\t]*)name server:(?>[\x20\t]*)(.+)$/im' => 'nameserver', 
                    '/(?>[\x20\t]*)status:(?>[\x20\t]*)(.+)$/im' => 'status'));

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