<?php

/**
 * A simple script to generate reserved network ranges
 * in markdown table format, or json.
 */

$ranges = [
    'Coin identifier (Mainnet)',
    'Testnet',
    'Regtest',
    'Altnet 3',
    'Altnet 4',
    'Altnet 5',
    'Altnet 6',
    'Altnet 7',
    'Altnet 8',
    'Altnet 9 '
];

$rows = [];
$rows[] = ['start index',
           'end index',
           'start hex',
           'end hex',
           'network index',
           'usage',
          ];             
             
$hexbase = '0x80000000';
$hexbaseint = hexdec($hexbase);
$increment = 100000000;
$start = 0;
$end = $start + $increment - 1;

foreach($ranges as $idx => $usage) {
    
    $start_hex = '0x' . strtoupper(dechex($hexbaseint + $start));
    $end_hex = '0x' . strtoupper(dechex($hexbaseint + $end));
    $rows[] =  [$start, $end, $start_hex, $end_hex, $idx,$usage];
    
    $start += $increment;
    $end += $increment;
}
$end = pow(2,31);
$start_hex = '0x' . strtoupper(dechex($hexbaseint + $start));
$end_hex = '0x' . strtoupper(dechex($hexbaseint + $end));

$rows[] = [$start, $end, $start_hex, $end_hex, '',
           'Reserved for future purposes'];

if(file_exists(__DIR__ . '/texttable_markdown.class.php')) {
    require_once(__DIR__ . '/texttable_markdown.class.php');
    echo texttable_markdown::table($rows, 'firstrow');
}
else {
    echo json_encode($rows, JSON_PRETTY_PRINT);
}
             
             