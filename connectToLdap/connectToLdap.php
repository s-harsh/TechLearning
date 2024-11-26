<?php

// Function to dynamically handle certificate validation
function connectToLdap($ldap_url, $ignore_cert = false) {
    // Parse the URL to extract the protocol and port
    $url_parts = parse_url($ldap_url);
    $protocol = isset($url_parts['scheme']) ? $url_parts['scheme'] : 'ldap';
    $port = isset($url_parts['port']) ? $url_parts['port'] : (($protocol === 'ldaps') ? 636 : 389);
    
    // Validate the protocol
    if (!in_array($protocol, ['ldap', 'ldaps'])) {
        die("Invalid protocol: $protocol. Only 'ldap' or 'ldaps' are allowed.");
    }

    // Set certificate validation based on the protocol and port
    if ($protocol === 'ldaps' && $port === 636) {
        if ($ignore_cert) {
            // Disable certificate validation
            putenv("LDAPTLS_REQCERT=never");
            ldap_set_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, LDAP_OPT_X_TLS_NEVER);
            echo "Certificate validation ignored for LDAPS connection on port 636.\n";
        } else {
            // Enforce certificate validation
            ldap_set_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, LDAP_OPT_X_TLS_DEMAND);
            echo "Certificate validation enabled for LDAPS connection on port 636.\n";
        }
    }

    // Establish LDAP connection
    $ldap_connection = ldap_connect($ldap_url);
    if (!$ldap_connection) {
        die("Failed to connect to LDAP server at $ldap_url.");
    }

    // Set LDAP options
    ldap_set_option($ldap_connection, LDAP_OPT_PROTOCOL_VERSION, 3);
    ldap_set_option($ldap_connection, LDAP_OPT_REFERRALS, 0);

    return $ldap_connection;
}