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
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * @namespace Novutec\WhoisParser
 */
namespace Novutec\WhoisParser;

/**
 * WhoisParser Config
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
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
	 * @return	void
	 */
    public function __construct($specialWhois = array())
    {
        if (empty($this->config)) {
            $this->config = parse_ini_file('whois.ini');
        }
        
        if (sizeof($specialWhois) > 0) {
            $this->config = array_replace($this->config, $specialWhois);
        }
    }

    /**
	 * Returns configuration for whois server by template
	 * 
	 * @param  string $template
	 * @return array
	 */
    public function get($template)
    {
        $template = strtolower($template);
        
        return array(
                'server' => isset($this->config[$template]['server']) ? $this->config[$template]['server'] : '', 
                'port' => isset($this->config[$template]['port']) ? $this->config[$template]['port'] : 43, 
                'format' => isset($this->config[$template]['format']) ? $this->config[$template]['format'] : '%domain%', 
                'template' => isset($this->config[$template]['template']) ? $this->config[$template]['template'] : $template, 
                'adapter' => isset($this->config[$template]['adapter']) ? $this->config[$template]['adapter'] : 'socket', 
                'dummy' => isset($this->config[$template]));
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