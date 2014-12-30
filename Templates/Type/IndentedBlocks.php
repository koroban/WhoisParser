<?php

namespace Novutec\WhoisParser\Templates\Type;

/**
 * Parser designed for parsing layouts where each section is separated by a clear line and the values are
 * indented by a tab.
 */
class IndentedBlocks extends KeyValue
{
    protected function parseRawData($rawdata)
    {
        $rawdata = str_replace(array("\r\n", "\r"), "\n", $rawdata);
        $blocks = explode("\n\n", $rawdata);

        $data = array();
        foreach ($blocks as $block) {
            $blockParts = explode(':', $block, 2);
            if (count($blockParts) < 2) {
                continue;
            }

            $key = trim($blockParts[0]);
            $value = trim($blockParts[1]);
            $value = preg_replace('/^\t+/im', '', $value);

            $data[$key] = $value;
        }

        return $data;
    }
}
