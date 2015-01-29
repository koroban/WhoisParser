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
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * @namespace Novutec\WhoisParser
 */
namespace Novutec\WhoisParser;

/**
 * @see Result/Result
 */
require_once 'Result/Result.php';

use Novutec\WhoisParser\Adapter\AbstractAdapter;
use Novutec\WhoisParser\Config\Config;
use Novutec\WhoisParser\Exception\AbstractException;
use Novutec\WhoisParser\Exception\NoAdapterException;
use Novutec\WhoisParser\Exception\NoQueryException;
use Novutec\WhoisParser\Exception\NoTemplateException;
use Novutec\WhoisParser\Exception\RateLimitException;
use Novutec\WhoisParser\Result\Result;
use Novutec\WhoisParser\Templates\Type\AbstractTemplate;

/**
 * WhoisParser
 * 
 * Automatically follows the WHOIS registry referral chains until it finds the
 * correct WHOIS for the most complete WHOIS data. Exceptionally robust WHOIS parser
 * that parses a variety of free form WHOIS data into well-structured data that your
 * application may read. Also returns an indication of whether a domain is available.
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Parser
{

    /**
     * WhoisParserConfig object
     * 
     * @var object
     * @access protected
     */
    protected $Config;

    /**
     * Query string sent to the WhoisParser
     * 
     * @var object
     * @access protected
     */
    protected $Query;

    /**
     * Raw output from whois server unformatted
     * 
     * @var string
     * @access protected
     */
    protected $rawdata;

    /**
     * WhoisParserResult object
     * 
     * @var \Novutec\WhoisParser\Result\Result
     * @access protected
     */
    protected $Result;

    /**
     * Should the exceptions be thrown or caugth and trapped in the response?
     * 
     * @var boolean
     * @access protected
     */
    protected $throwExceptions = false;

    /**
     * Contains special whois server like member whois configuration. It will be
     * used to overload the respective template in WhoisParserConfig.
     * 
     * @var array
     * @access protected
     */
    protected $specialWhois = array();

    /**
     * Output format 'object', 'array', 'json', 'serialize' or 'xml'
     *
     * @var string
     * @access protected
     */
    protected $format = 'object';

    /**
     * Output format for dates
     * 
     * @var string
     * @access protected
     */
    protected $dateformat = '%Y-%m-%d %H:%M:%S';

    /**
     * Activate cache
     * 
     * @var string Cache location
     * @access protected
     */
    protected $cachePath = null;

    /**
     * Rate limited servers list.
     * Allows us to prevent additional queries. Must be cleared manually.
     *
     * @var array List of servers which are currently rate limited
     */
    protected $rateLimitedServers = array();

    protected $customConfigFile = null;

    protected $proxyConfigFile = null;

    protected $customTemplateNamespace = null;

    protected $customAdapterNamespace = null;

    /**
     * @var array Custom domain groups for DomainParser
     */
    protected $customDomainGroups = array();


    /**
     * Creates a WhoisParser object
     * 
     * @param  string $format
	 */
    public function __construct($format = 'object')
    {
        $this->setFormat($format);
    }

    /**
     * Set special whois server like member whois configuration. It will be
     * used to overload the respective template in WhoisParserConfig.
     * 
     * @param  array $specialWhois
	 * @return void
	 */
    public function setSpecialWhois($specialWhois)
    {
        $this->specialWhois = $specialWhois;
    }

    /**
	 * Lookup an IP address (ipv4 and ipv6) and domain names
	 * 
	 * @throws NoQueryException
	 * @throws instance of AbstractException if throwExceptions = true
	 * @param  string $query
	 * @return object
	 */
    public function lookup($query = '')
    {
        $this->Result = new Result();
        $this->Config = new Config($this->specialWhois, $this->customConfigFile);
        
        try {
            if ($query == '') {
                throw new NoQueryException('No lookup query given');
            }
            
            $this->prepare($query);
            
            if (isset($this->Query->ip)) {
                $config = $this->Config->get('iana');
            } else {
                if (isset($this->Query->tldGroup)) {
                    $config = $this->Config->get($this->Query->tldGroup, $this->Query->idnTld);
                } else {
                    $config = $this->Config->get($this->Query->asn);
                }
                
                if ($config['server'] == '' || $this->Query->domain == '') {
                    $config = $this->Config->get('iana');
                }
            }
            
            $this->Config->setCurrent($config);
            $this->call();
        } catch (AbstractException $e) {
            if ($this->throwExceptions) {
                throw $e;
            }
            
            $this->Result->addItem('exception', $e->getMessage());
            $this->Result->addItem('rawdata', $this->rawdata);
            
            if (isset($this->Query)) {
                
                if (isset($this->Query->ip)) {
                    $this->Result->addItem('name', $this->Query->ip);
                } else {
                    $this->Result->addItem('name', $this->Query->fqdn);
                }
            } else {
                $this->Result->addItem('name', $query);
            }
        }
        
        // call cleanUp method
        $this->Result->cleanUp($this->Config->getCurrent(), $this->dateformat);
        
        // peparing output of Result by format
        switch ($this->format) {
            case 'json':
                return $this->Result->toJson();
                break;
            case 'serialize':
                return $this->Result->serialize();
                break;
            case 'array':
                return $this->Result->toArray();
                break;
            case 'xml':
                return $this->Result->toXml();
                break;
            default:
                return $this->Result;
        }
    }

    /**
     * Parses the given query to get either the domain name or an IP address
     * 
     * @param  string $query
     * @return void
     */
    private function prepare($query)
    {
        // check if given query is an IP address and AS number or possible
        // domain name
        if ($this->bin2ip($this->ip2bin($query)) === $query) {
            $this->Query = new \stdClass();
            $this->Query->ip = $query;
        } elseif (preg_match('/^AS[0-9]*$/im', $query)) {
            $this->Query = new \stdClass();
            $this->Query->asn = $query;
        } else {
            $Parser = new \Novutec\DomainParser\Parser();
            $Parser->setCustomDomainGroups($this->customDomainGroups);
            if ($this->cachePath !== null) {
                $Parser->setCachePath($this->cachePath);
            }
            $this->Query = $Parser->parse(filter_var($query, FILTER_SANITIZE_STRING));
        }
    }

    /**
     * Send data to whois server and call parse() to process rawdata
     * 
     * @throws NoAdapterException
     * @throws RateLimitException
     * @param  string $query
	 * @return void
	 */
    public function call($query = '')
    {
        $this->rawdata = null;
        if ($query != '') {
            $this->Query = filter_var($query, FILTER_SANITIZE_STRING);
        }
        
        $Config = $this->Config->getCurrent();
        $Adapter = AbstractAdapter::factory($Config['adapter'], $this->proxyConfigFile, $this->customAdapterNamespace);
        $server = $Config['server'];

        if (in_array($server, $this->rateLimitedServers)) {
            throw new RateLimitException("Rate limit exceeded for server: ". $server);
        }

        if ($Adapter instanceof AbstractAdapter) {
            $this->rawdata = $Adapter->call($this->Query, $Config);
            $this->parse();
        } else {
            throw new NoAdapterException('Adapter '. $Config['adapter'] .' could not be found');
        }
    }

    /**
     * Parses rawdata from whois server and call postProcess if exists afterwards
     * 
     * @throws NoTemplateException
     * @throws RateLimitException
     * @return void
     */
    private function parse()
    {
        $Config = $this->Config->getCurrent();

        $Template = AbstractTemplate::factory($Config['template'], $this->customTemplateNamespace);

        // If Template is null then we do not have a template for that, but we
        // can still proceed to the end with just the rawdata
        if ($Template instanceof AbstractTemplate) {
            $this->Result->template[$Config['server']] = $Config['template'];
            $this->rawdata = $Template->translateRawData($this->rawdata, $Config);
            try {
                $Template->parse($this->Result, $this->rawdata, $this->Query);
            } catch (RateLimitException $e) {
                $server = $Config['server'];
                if (!in_array($server, $this->rateLimitedServers)) {
                    $this->rateLimitedServers[] = $server;
                }
                throw new RateLimitException("Rate limit exceeded for server: ". $server);
            }
            
            // set rawdata to Result - this happens here because sometimes we
            // have to fix the rawdata as well in postProcess
            $this->Result->addItem('rawdata', $this->rawdata);

            // set registered to Result
            $this->Result->addItem('registered', isset($this->Result->registered) ? $this->Result->registered : false);
            
            if (! isset($this->Result->whoisserver)) {
                $this->Result->addItem('whoisserver', $Config['server']);
            }
            
            // start post processing
            $Template->postProcess($this);
            
            // set name to Result
            if (isset($this->Query->tld) && ! isset($this->Query->fqdn)) {
                $this->Result->addItem('name', $this->Query->tld);
            } elseif (isset($this->Query->ip)) {
                $this->Result->addItem('name', $this->Query->ip);
            } elseif (isset($this->Query->asn)) {
                $this->Result->addItem('name', $this->Query->asn);
            } else {
                $this->Result->addItem('name', $this->Query->fqdn);
                $this->Result->addItem('idnName', $this->Query->idnFqdn);
            }
        } else {
            throw new NoTemplateException('Template '. $Config['template'] .' could not be found');
        }
    }

    /**
     * Converts IP address to binary
     * 
     * @param  string $ip
     * @return mixed
     */
    private function ip2bin($ip)
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            return base_convert(ip2long($ip), 10, 2);
        }
        
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
            return false;
        }
        
        if (($ip_n = inet_pton($ip)) === false) {
            return false;
        }
        
        $bits = 15; // 16 x 8 bit = 128bit (ipv6)
        $ipbin = '';
        
        while ($bits >= 0) {
            $bin = sprintf('%08b', (ord($ip_n[$bits])));
            $ipbin = $bin . $ipbin;
            $bits = $bits - 1;
        }
        
        return $ipbin;
    }

    /**
     * Converts binary to IP address
     * 
     * @param  string $bin
     * @return mixed
     */
    private function bin2ip($bin)
    {
        if (strlen($bin) <= 32) {
            // 32bits (ipv4)
            return long2ip(base_convert($bin, 2, 10));
        }
        
        if (strlen($bin) !== 128) {
            return false;
        }
        
        $pad = 128 - strlen($bin);
        
        for ($i = 1; $i <= $pad; $i++) {
            $bin = '0' . $bin;
        }
        
        $bits = 0;
        $ipv6 = '';
        
        while ($bits <= 7) {
            $bin_part = substr($bin, ($bits * 16), 16);
            $ipv6 = $ipv6 . dechex(bindec($bin_part)) . ':';
            $bits = $bits + 1;
        }
        
        return inet_ntop(inet_pton(substr($ipv6, 0, - 1)));
    }

    /**
     * Returns WhoisParserResult instance
     * 
     * @return object
     */
    public function getResult()
    {
        return $this->Result;
    }


    public function getRawData()
    {
        return $this->rawdata;
    }

    /**
     * Returns WhoisParserConfig instance
     * 
     * @return object
     */
    public function getConfig()
    {
        return $this->Config;
    }

    /**
     * Returns WhoisParser Query
     *
     * @return object
     */
    public function getQuery()
    {
        return $this->Query;
    }

    /**
     * Set output format
     *
     * You may choose between 'object', 'array', 'json', 'serialize' or 'xml' output format
     *
     * @param  string $format
     * @return void
     */
    public function setFormat($format = 'object')
    {
        $this->format = filter_var($format, FILTER_SANITIZE_STRING);
    }

    /**
     * Set date format
     * 
     * You may choose your own date format. Please check http://php.net/strftime for further
     * details
     * 
     * @param  string $dateformat
     * @return void
     */
    public function setDateFormat($dateformat = '%Y-%m-%d %H:%M:%S')
    {
        $this->dateformat = $dateformat;
    }


    /**
     * Set the throwExceptions flag
     *
     * Set whether exceptions encounted in the dispatch loop should be thrown
     * or caught and trapped in the response object.
     *
     * Default behaviour is to trap them in the response object; call this
     * method to have them thrown.
     *
     * @param  boolean $throwExceptions
     * @return void
     */
    public function throwExceptions($throwExceptions = false)
    {
        $this->throwExceptions = filter_var($throwExceptions, FILTER_VALIDATE_BOOLEAN);
    }


    /**
     * Set the path to use for on-disk cache. If NULL, cache is disabled.
     *
     * @param string|null $path Cache path
     */
    public function setCachePath($path)
    {
        $this->cachePath = $path;
    }


    /**
     * Return the list of rate limited servers
     *
     * @return array
     */
    public function getRateLimitedServers()
    {
        return $this->rateLimitedServers;
    }


    /**
     * Remove a specific server from the list of rate limited servers.
     *
     * @param string $server
     * @return bool Server was present in list?
     */
    public function removeRateLimitedServer($server)
    {
        $key = array_search($server, $this->rateLimitedServers);
        if ($key !== false) {
            unset($this->rateLimitedServers[$key]);
        }
        return ($key !== false);
    }


    /**
     * Clear the list of rate limited servers
     *
     * @return int Number of entries removed from list
     */
    public function clearRateLimitedServers()
    {
        $count = count($this->rateLimitedServers);
        $this->rateLimitedServers = array();
        return $count;
    }


    /**
     * Add a specific server to the list of rate limited servers
     * @param string $server Server name
     */
    public function addRateLimitedServer($server)
    {
        $this->rateLimitedServers[] = $server;
    }


    /**
     * Set a custom config file.
     * Settings in this file will override the default config.
     * Set to NULL to clear.
     *
     * @param null|string $iniFile INI file
     */
    public function setCustomConfigFile($iniFile)
    {
        $this->customConfigFile = $iniFile;
    }


    /**
     * Set a proxy config file.
     * Set to NULL to clear.
     *
     * @param null|string $iniFile
     */
    public function setProxyConfigFile($iniFile)
    {
        $this->proxyConfigFile = $iniFile;
    }


    /**
     * Set a custom template namespace
     * Templates in this namespace will override the default templates.
     * Set to NULL to clear.
     *
     * @param null|string $namespace
     */
    public function setCustomTemplateNamespace($namespace)
    {
        $this->customTemplateNamespace = $namespace;
    }


    /**
     * Set a custom adapter namespace.
     * Adapters in this namespace will override the default adapters.
     * Set to NULL to clear.
     *
     * @param null|string $namespace
     */
    public function setCustomAdapterNamespace($namespace)
    {
        $this->customAdapterNamespace = $namespace;
    }


    /**
     * Add a custom domain group for DomainParser. This will override the built-in domain groups.
     *
     * @param string $groupName
     * @param array $tldList
     */
    public function addCustomDomainGroup($groupName, array $tldList)
    {
        $this->customDomainGroups[$groupName] = $tldList;
    }


    /**
     * Set the custom domain groups for DomainParser. The array should be in the same format as in Additional.php.
     * These will override the built-in domain groups
     *
     * @param array $domainGroups Array of domain groups and their tld lists
     */
    public function setCustomDomainGroups(array $domainGroups)
    {
        $this->customDomainGroups = $domainGroups;
    }



    /**
     * Return the current configured proxy config file location
     *
     * @return null|string
     */
    public function getProxyConfigFile()
    {
        return $this->proxyConfigFile;
    }


    /**
     * Return the currently configured custom adapter namespace.
     *
     * @return null|string
     */
    public function getCustomAdapterNamespace()
    {
        return $this->customAdapterNamespace;
    }
}
