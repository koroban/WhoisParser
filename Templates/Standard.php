<?php

namespace Novutec\WhoisParser\Templates;

use Novutec\WhoisParser\Templates\Type\KeyValue;

/**
 * A 'standard' template that will parse most key: value reponses
 *
 * @package Novutec\WhoisParser\Templates
 */
class Standard extends KeyValue
{

    protected $regexKeys = array(
        'name' => '/^Domain Name$/i',
        'ask_whois' => '/^(Registrar )?Whois Server$/i',
        'created' => '/^(Domain |Record )?(Creat|Registrat|Register)(e|ed|ion)( On| Date)?$/i',
        'expires' => '/^(Domain )?(Registration |Registry )?(Expiration|Expires|Expiry) (On|Date)$/i',
        'changed' => '/^(Domain )?(Last )?Updated (On|Date)$/i',
        'nameserver' => '/^(Name Server|Name Server Name|Nameservers)$/i',
        'dnssec' => '/^DNSSEC/i',
        'status' => '/^(Domain )?Status$/i',

        // Registrar
        'registrar:id' => '/^(Sponsoring )?Registrar (IANA )?ID$/i',
        'registrar:email' => '/^(Sponsoring )?Registrar Abuse Contact Email$/i',
        'registrar:name' => '/^(Sponsoring )?Registrar( Organization)?$/i',
        'registrar:phone' => '/^(Sponsoring )?Registrar (Abuse Contact )?Phone$/i',
        'registrar:url' => '/^(Sponsoring )?(Referral|Registrar) URL$/i',

        // Contacts: Owner
        'contacts:owner:handle' => '/^(Registry )?(Registrant|Owner)(\-| )ID$/i',
        'contacts:owner:name' => '/^(Registrant|Owner)(\-| )(Contact Name|Name)$/i',
        'contacts:owner:organization' => '/^(Registrant|Owner)( Organization)?$/i',
        'contacts:owner:address' => '/^(Registrant|Owner)(\-| )(Street|Address)[0-9]*$/i',
        'contacts:owner:city' => '/^(Registrant|Owner)(\-| )City$/i',
        'contacts:owner:state' => '/^(Registrant|Owner)(\-| )State(\/Province)?$/i',
        'contacts:owner:zipcode' => array (
            '/^(Registrant|Owner)(\-| )Postal(\-| )Code$/i',
            '/^(Registrant|Owner)(\-| )ZIP$/i'
        ),
        'contacts:owner:country' => '/^(Registrant|Owner)(\-| )Country(\/Economy)*$/i',
        'contacts:owner:phone' => '/^(Registrant|Owner)(\-| )Phone$/i',
        'contacts:owner:fax' => '/^(Registrant|Owner)(\-| )FAX$/i',
        'contacts:owner:email' => '/^(Registrant|Owner)(\-| )(Contact )?(Email|E-Mail)$/i',

        // Contacts: Admin
        'contacts:admin:handle' => '/^(Registry )?Admin(istrative)?(\-| )(Contact )?ID$/i',
        'contacts:admin:name' => '/^Admin(istrative)?(\-| )(Contact )?Name$/i',
        'contacts:admin:organization' => '/^Admin(istrative)?(\-| )(Contact )?Organization$/i',
        'contacts:admin:address' => '/^Admin(istrative)?(\-| )(Contact )?(Street|Address)[0-9]*$/i',
        'contacts:admin:city' => '/^Admin(istrative)?(\-| )(Contact )?City$/i',
        'contacts:admin:state' => '/^Admin(istrative)?(\-| )(Contact )?State(\/Province)?$/i',
        'contacts:admin:zipcode' => array (
            '/^Admin(istrative)?(\-| )(Contact )?Postal(\-| )Code$/i',
            '/^Admin(istrative)?(\-| )(Contact )?ZIP$/i'
        ),
        'contacts:admin:country' => '/^Admin(istrative)?(\-| )(Contact )?Country(\/Economy)*$/i',
        'contacts:admin:phone' => '/^Admin(istrative)?(\-| )(Contact )?Phone$/i',
        'contacts:admin:fax' => '/^Admin(istrative)?(\-| )(Contact )?FAX$/i',
        'contacts:admin:email' => '/^Admin(istrative)?(\-| )(Contact )?(Email|E-Mail)$/i',

        // Contacts: Tech
        'contacts:tech:handle' => '/^(Registry )?Tech(nical)?(\-| )(Contact )?ID$/i',
        'contacts:tech:name' => '/^Tech(nical)?(\-| )(Contact )?Name$/i',
        'contacts:tech:organization' => '/^Tech(nical)?(\-| )(Contact )?Organization$/i',
        'contacts:tech:address' => '/^Tech(nical)?(\-| )(Contact )?(Street|Address)[0-9]*$/i',
        'contacts:tech:city' => '/^Tech(nical)?(\-| )(Contact )?City$/i',
        'contacts:tech:state' => '/^Tech(nical)?(\-| )(Contact )?State(\/Province)?$/i',
        'contacts:tech:zipcode' => array (
            '/^Tech(nical)?(\-| )(Contact )?Postal(\-| )Code$/i',
            '/^Tech(nical)?(\-| )(Contact )?ZIP$/i'
        ),
        'contacts:tech:country' => '/^Tech(nical)?(\-| )(Contact )?Country(\/Economy)*$/i',
        'contacts:tech:phone' => '/^Tech(nical)?(\-| )(Contact )?Phone$/i',
        'contacts:tech:fax' => '/^Tech(nical)?(\-| )(Contact )?FAX$/i',
        'contacts:tech:email' => '/^Tech(nical)?(\-| )(Contact )?(Email|E-Mail)$/i',

        // Contacts: Billing
        'contacts:billing:handle' => '/^(Registry )?Billing(\-| )(Contact )?ID$/i',
        'contacts:billing:name' => '/^Billing(\-| )(Contact )?Name$/i',
        'contacts:billing:organization' => '/^Billing(\-| )(Contact )?Organization$/i',
        'contacts:billing:address' => '/^Billing(\-| )(Contact )?(Street|Address)[0-9]*$/i',
        'contacts:billing:city' => '/^Billing(\-| )(Contact )?City$/i',
        'contacts:billing:state' => '/^Billing(\-| )(Contact )?State(\/Province)?$/i',
        'contacts:billing:zipcode' => array (
            '/^Billing(\-| )(Contact )?Postal(\-| )Code$/i',
            '/^Billing(\-| )(Contact )?ZIP$/i'
        ),
        'contacts:billing:country' => '/^Billing(\-| )(Contact )?Country(\/Economy)*$/i',
        'contacts:billing:phone' => '/^Billing(\-| )(Contact )?Phone$/i',
        'contacts:billing:fax' => '/^Billing(\-| )(Contact )?FAX$/i',
        'contacts:billing:email' => '/^Billing(\-| )(Contact )?(Email|E-Mail)$/i',
    );

    protected $available = array(
        '/(Available\s*Domain:|Status: free|No match|No Object Found|Domain (name )?not found|Domain Status: Available| is not registered|Not found: |No data found)/i',
        '/^\s*(Object )?Not Found(\.\.\.)?\s*$/i',
        '/^\s*# Not found\s*/im',
        '/Domain "([^"]+)" is available for registration/i',
    );

    protected $availabilityField = 'status';

    protected $availabilityValues = array('available', 'not registered', 'free');

    protected $rateLimit = '/(Quota Exceeded|exceeded the maximum allowable|exceeded your query limit|restricted due to excessive queries)|WHOIS LIMIT EXCEEDED|due to query limit controls|You have exceeded you allotted number of|Maximum Daily connection limit reached./i';


    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();

        // check if there was another whois server
        if (isset($ResultSet->ask_whois)) {
            $Config = $WhoisParser->getConfig();
            $curConfig = $Config->getCurrent();
            if (strtolower(trim($curConfig['server'])) != strtolower(trim($ResultSet->ask_whois))) {
                $newConfig = $Config->get(trim($ResultSet->ask_whois));
                $newConfig['server'] = trim($ResultSet->ask_whois);
                unset($ResultSet->ask_whois);

                $Config->setCurrent($newConfig);
                $WhoisParser->call();
            }
        }
    }
}
