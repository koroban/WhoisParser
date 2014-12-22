<?php

namespace Novutec\WhoisParser\Templates\Type;

/**
 * Some servers can't be served by a single template (for example, because they return different output based on
 * the TLD being requested), so we use a proxy template which decides which template to actually use, then passes
 * all requests to that template.
 */
class Proxy extends AbstractTemplate
{

    /**
     * @var null|AbstractTemplate
     */
    protected $template = null;

    /**
     * @param \Novutec\WhoisParser\Result\Result $result
     * @param $rawdata
     * @param string|object $query
     */
    public function parse($result, $rawdata, $query)
    {
        $this->template->parse($result, $rawdata, $query);
    }


    public function translateRawData($rawdata, $config)
    {
        return $this->template->translateRawData($rawdata, $config);
    }


    public function postProcess(&$WhoisParser)
    {
        $this->template->postProcess($WhoisParser);
    }
}
