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
 * @namespace Novutec\WhoisParser\Config
 */
namespace Novutec\WhoisParser\Config;

/**
 * WhoisParser Config
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Config
{

    /**
	 * Contains the server, port, format and template for all whois servers
	 * If format is not defined it will be only the domain name
	 * If port is not defined it will be the default port 43
	 * 
	 * @var array
	 * @access protected
	 */
    protected $config;

    /**
     * Contains custom configuration
     *
     * @var array
     */
    protected $customConfig;

    /**
     * Name of the current loaded configuration
     * 
     * @var array
     * @access protected
     */
    protected $current;

    /**
	 * Creates a WhoisParserConfig object and parses ini files for configuration.
	 * If $special_whois is set it will overload the respective handler with
	 * another configuration.
	 * 
	 * @param  array $specialWhois
     * @param string $customIni Custom config (overrides default config)
	 * @return	void
	 */
    public function __construct($specialWhois = array(), $customIni = null)
    {
        if (empty($this->config)) {
            $this->config = parse_ini_file('whois.ini');
            if (strlen($customIni)) {
                $this->customConfig = parse_ini_file($customIni);
            }
        }
        
        if (sizeof($specialWhois) > 0) {
            $this->config = array_replace($this->config, $specialWhois);
        }
    }

    /**
	 * Returns configuration for whois server by template
	 * You may specify a tld. If tld is given it will look up for the tld instead
	 * of looking up for template. This is needed if tlds are within the same
	 * group but have different templates like CentralNic
	 * 
	 * @param  string $template
	 * @param  string $tld
	 * @return array
	 */
    public function get($template, $tld = '')
    {
        $template = strtolower($template);

        if (strlen($tld)) {
            if ((isset($this->customConfig[$tld])) || isset($this->config[$tld])) {
                $template = strtolower($tld);
            }
        }

        $defaults = array(
            'server' => '',
            'port' => 43,
            'format' => '%domain%',
            'template' => $template,
            'adapter' => 'socket',
            'dummy' => true,
        );

        $config = $defaults;
        if (isset($this->customConfig[$template])) {
            $config = array_merge($defaults, $this->customConfig[$template]);
            $config['dummy'] = false;
        } else if (isset($this->config[$template])) {
            $config = array_merge($defaults, $this->config[$template]);
            $config['dummy'] = false;
        }
        return $config;
    }

    /**
     * Set the current configuration
     * 
     * @param  array $newConfig
     * @return void
     */
    public function setCurrent($newConfig)
    {
        $this->current = $newConfig;
    }

    /**
     * Returns the currenct configuration
     * @return array
     */
    public function getCurrent()
    {
        return $this->current;
    }
}