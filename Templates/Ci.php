<?php

namespace Novutec\WhoisParser\Templates;

use Novutec\WhoisParser\Adapter\AbstractAdapter;
use Novutec\WhoisParser\Templates\Type\KeyValue;

class Ci extends KeyValue
{
    protected $regexKeys = array(
        'name' => '/^Domain$/i',
        'ask_whois' => '/^(Registrar )?Whois Server$/i',
        'created' => '/^Created$/i',
        'expires' => '/^Expiration date$/i',
        'nameserver' => '/^Nameserver$/i',
        'registrar:name' => '/^Registrar$/i',
        'contacts:owner:handle' => '/^Owner\'s handle$/i',
        'contacts:admin:handle' => '/^Administrative Contact\'s handle$/i',
        'contacts:tech:handle' => '/^Technical Contact\'s handle$/i',
    );

    protected $regexKeysContacts = array(
//        ':handle' => '/^Handle$/i',
        ':created' => '/^Created$/i',
        ':changed' => '/^Last modified$/i',
        ':name' => '/^Name$/i',
        ':email' => '/^Email$/i',
        ':phone' => '/^Phone$/i',
        ':fax' => '/^Fax$/i',
        ':address' => '/^Address$/i',
        ':city' => '/^City$/i',
        ':country' => '/^Country$/i',
    );

    protected $available = array(
        '/Domain ([^\s]+) not found/i',
    );

    protected $rateLimit = '/(Quota Exceeded|exceeded the maximum allowable|exceeded your query limit)/i';


    public function postProcess(&$whoisParser)
    {
        $whoisResult = $whoisParser->getResult();
        $configObj = $whoisParser->getConfig();
        $config = $configObj->getCurrent();
        $proxyConfig = $whoisParser->getProxyConfigFile();
        $customNamespace = $whoisParser->getCustomAdapterNamespace();
        $adapter = AbstractAdapter::factory('socket', $proxyConfig, $customNamespace);

        // Fetch additional contacts
        $contactKeys = array(
            'contacts:owner' => 'Owner\'s handle',
            'contacts:admin' => 'Administrative Contact\'s handle',
            'contacts:tech' => 'Technical Contact\'s handle',
        );
        $seenContacts = array();
        foreach ($contactKeys as $contactKey => $handleKey) {
            if (! array_key_exists($handleKey, $this->data)) {
                continue;
            }

            $handle = $this->data[$handleKey];
            if (array_key_exists($handle, $seenContacts)) {
                $data = $seenContacts[$handle];
            } else {
                $config['format'] = $handle;
                $result = $adapter->call($handle, $config);
                $result = $this->translateRawData($result, $config);
                $whoisResult->addItem('rawdata', $result);

                $data = $this->parseRawData($result);
                $seenContacts[$handle] = $data;
            }

            if (array_key_exists('Firstname', $data) && array_key_exists('Name', $data)) {
                $data['Name'] = trim($data['Firstname'] .' '. $data['Name']);
            }

            $regexContacts = array();
            foreach ($this->regexKeysContacts as $key => $regex) {
                $regexContacts[$contactKey . $key] = $regex;
            }
            $this->parseKeyValues($whoisResult, $data, $regexContacts, true);

            $type = (array_key_exists('Person', $data) && ($data['Person'] == 'True') ? 'Person' : 'Organization');
            $this->result->addItem($contactKey .':type', $type);
            if ($type == 'Organization') {
                $this->result->addItem($contactKey .':organization', $data['Name']);
                $this->result->addItem($contactKey .':name', null);
            }
        }

    }

}
