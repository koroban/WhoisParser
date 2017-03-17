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
 * @namespace Novutec\WhoisParser\Templates
 */
namespace Novutec\WhoisParser\Templates;

use Novutec\WhoisParser\Templates\Type\Regex;

/**
 * Template for whois.domrobot.com
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Gtld_domrobot extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks;


    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems;


    /**
     * Contact types with the same structure 
     * 
     * @var array
     * @access protected
     */
	const CONTACTS = [
		'admin' => 'admin',
		'tech' => 'tech',
		'billing' => 'billing',
		'registrant' => 'registrant',
	];



	public function __construct() {
		$this->blocks = [
			1 => '/^[\s\n\r]*[^:]*:[\s\n\r]*(.*)$/im',
            2 => '/\s*name\s*server\s*:(?>[\x20\t]*)(.*?)(?=dnssec)|$/is'
		];

		$items = [];
		/**
         * Create contact specific regexps from base template
         */
		foreach(self::CONTACTS as $regexp => $property) {
			$items['/^\s*' . $regexp . '\s*name\s*:(?>[\x20\t]*)(.*?)$/im'] = 'contacts:' . $property . ':name';
    		$items['/^\s*' . $regexp . '\s*organization\s*:(?>[\x20\t]*)(.*?)$/im'] = 'contacts:' . $property . ':organization';
    		$items['/^\s*' . $regexp . '\s*street\s*:(?>[\x20\t]*)(.*?)$/im'] = 'contacts:' . $property . ':street';
    		$items['/^\s*' . $regexp . '\s*city\s*:(?>[\x20\t]*)(.*?)$/im'] = 'contacts:' . $property . ':city';
    		$items['/^\s*' . $regexp . '\s*state\/province\s*:(?>[\x20\t]*)(.*?)$/im'] = 'contacts:' . $property . ':state';
    		$items['/^\s*' . $regexp . '\s*postal\s*code\s*:(?>[\x20\t]*)(.*?)$/im'] = 'contacts:' . $property . ':zipcode';
    		$items['/^\s*' . $regexp . '\s*country\s*:(?>[\x20\t]*)(.*?)$/im'] = 'contacts:' . $property . ':country';
    		$items['/^\s*' . $regexp . '\s*phone\s*:(?>[\x20\t]*)(.*?)$/im'] = 'contacts:' . $property . ':phone';
    		$items['/^\s*' . $regexp . '\s*phone\s*ext\s*:(?>[\x20\t]*)(.*?)$/im'] = 'contacts:' . $property . ':phone_ext';
    		$items['/^\s*' . $regexp . '\s*fax\s*:(?>[\x20\t]*)(.*?)$/im'] = 'contacts:' . $property . ':fax';
    		$items['/^\s*' . $regexp . '\s*fax\s*ext\s*:(?>[\x20\t]*)(.*?)$/im'] = 'contacts:' . $property . ':fax_ext';
    		$items['/^\s*' . $regexp . '\s*email\s*:(?>[\x20\t]*)(.*?)$/im'] = 'contacts:' . $property . ':email';
    		$items['/^\s*registry\s*' . $regexp . '\s*id\s*:(?>[\x20\t]*)(.*?)$/im'] = 'contacts:' . $property . ':id';
    	}

    	/**
    	 * Domain data
    	 */
    	$items['/^\s*dnssec\s*:(?>[\x20\t]*)(.*?)$/im'] = 'domain:dnssec';
    	$items['/^\s*updated\s*date\s*:(?>[\x20\t]*)(.*?)$/im'] = 'domain:updated_date';
    	$items['/^\s*creation\s*date\s*:(?>[\x20\t]*)(.*?)$/im'] = 'domain:creation_date';
    	$items['/^\s*domain\s*name\s*:(?>[\x20\t]*)(.*?)$/im'] = 'domain:name';
    	$items['/^\s*domain\s*status\s*:(?>[\x20\t]*)(.*?)$/im'] = 'domain:status';
    	$items['/^\s*registry\s*domain\s*id\s*:(?>[\x20\t]*)(.*?)$/im'] = 'domain:id';
    	$items['/^\s*internationalized\s*domain\s*name\s*:(?>[\x20\t]*)(.*?)$/im'] = 'domain:idna';

    	/**
    	 * Server data
    	 */
    	$items['/^\s*>>>\s*last\s*update\s*of\s*whois\s*database\s*:(?>[\x20\t]*)(.*?)\s*<<<\s*$/im'] = 'server:last_update';

    	/**
    	 * Registrar data
    	 */ 
    	$items['/^\s*registrar\s*:(?>[\x20\t]*)(.*?)$/im'] = 'registrar:name';
    	$items['/^\s*registrar\s*iana\s*id\s*:(?>[\x20\t]*)(.*?)$/im'] = 'registrar:iana_id';
    	$items['/^\s*registrar\s*abuse\s*contact\s*email\s*:(?>[\x20\t]*)(.*?)$/im'] = 'registrar:abuse_email';
    	$items['/^\s*registrar\s*abuse\s*contact\s*phone\s*:(?>[\x20\t]*)(.*?)$/im'] = 'registrar:abuse_phone';
    	
    	$this->blockItems = [
    		1 => $items,
            2 => [
                '/^\s*name\s*server\s*:(?>[\x20\t]*)(.*?)$/im' => 'domain:nameservers:nameserver'
    	   ]
        ];
    	
	}

 
}