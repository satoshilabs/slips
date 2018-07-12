<?php

/**
 * A simple script to generate example calculations
 * in markdown table format, or json.
 */

$networks = [
    'Mainnet',
    'Testnet',
    'Regtest',
    'Altnet 3',
    'Altnet 4',
    'Altnet 5',
    'Altnet 6',
    'Altnet 7',
    'Altnet 8',
    'Altnet 9',
];

$coins = [
    0 =>        'Bitcoin',
    1 =>        'Litecoin',
    100 =>      'Bigup',
    91927009 => 'kUSD',
];
             
$hexbase = 0x80000000;
$network_multiplier = 100000000;

// First table.
$rows = [];
$rows[] = ['coin',
           'index',
           'network',
           'calculation',
           'index (altnet)',
           'hex (altnet)',
          ];             
foreach($coins as $coin_type => $coin) {
    foreach($networks as $network_index => $netname) {
        $calc_str = sprintf('%s + (%s * %s)', $coin_type, $network_index, $network_multiplier);
        $result = $coin_type + ($network_index * $network_multiplier);
        $hex = sprintf('0x%X', $result + $hexbase);
        
        $rows[] =  [$coin, $coin_type, $netname, $calc_str, $result, $hex];
    }
}
print_rows($rows);
echo "\n";


// Second table.
$rows = [];
$rows[] = ['coin',
           'index',
           'network',
           'calculation',
           'index (mainnet)',
           'hex (mainnet)',
          ];
foreach($coins as $coin_type => $coin) {
    foreach($networks as $network_index => $netname) {
        $altnet_id = $coin_type + ($network_index * $network_multiplier);
        $calc_str = sprintf('%s - (%s * %s)', $altnet_id, $network_index, $network_multiplier);
        $result = $altnet_id - ($network_index * $network_multiplier);
        $hex = sprintf('0x%X', $result + $hexbase);
        
        $rows[] =  [$coin, $altnet_id, $netname, $calc_str, $result, $hex];
    }
}
print_rows($rows);


function print_rows($rows) {
    if(file_exists(__DIR__ . '/texttable_markdown.class.php')) {
        require_once(__DIR__ . '/texttable_markdown.class.php');
        echo texttable_markdown::table($rows, 'firstrow');
    }
    else {
        echo json_encode($rows, JSON_PRETTY_PRINT);
    }
}
             
             