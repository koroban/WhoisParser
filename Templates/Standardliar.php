<?php

namespace Novutec\WhoisParser\Templates;

use Novutec\WhoisParser\Result\Result;

/**
 * Some DNS servers have been found to lie about domain status, causing a domain that we already know is registered
 * to be incorrectly reported as unregistered.
 *
 * This template resolves this issue by ignoring an unregistered state if the domain is already considered registered.
 */
class Standardliar extends Standard
{

    public function parse($result, $rawdata, $query)
    {
        $tmpResult = new Result();

        parent::parse($tmpResult, $rawdata, $query);

        if (isset($tmpResult->registered) && (!$tmpResult->registered)) {
            return;
        }

        $result->mergeFrom($tmpResult);
    }
}
