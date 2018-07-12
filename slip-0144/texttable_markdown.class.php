<?php

// be safe and sane.  use strictmode if available via composer.
$autoload_file = __DIR__ . '/vendor/autoload.php';
if( file_exists( $autoload_file )) {
    require_once($autoload_file);
    \strictmode\initializer::init();
}

/***
 * A class to print text in human friendly markdown tables.
 */
class texttable_markdown {

    /**
     * Formats a fixed-width text table, with borders.
     *
     * @param $rows  array of rows.  each row contains table cells.
     * @param $headertype  keys | firstrow
     * @param $empty_row_string  String to use when there is no data, or null.
     */
    static public function table( $rows, $headertype = 'keys', $empty_row_string = 'No Data' ) {
        
        if( !@count( $rows ) ) {
            
            if( $empty_row_string !== null ) {
                $rows = [ [ $empty_row_string ] ];
            }
            else {
                return '';
            }
        }

        $header = null;
        if( $headertype == 'keys' ) {        
            $header = array_keys( static::obj_arr( $rows[0] ) );
        }
        else if( $headertype == 'firstrow' ) {
            $header = static::obj_arr( array_shift( $rows ) );
        }
        
        $col_widths = array();
        
        static::calc_row_col_widths_and_align( $col_widths, $align, $header );
        foreach( $rows as $row ) {
            $row = static::obj_arr( $row );
            static::calc_row_col_widths_and_align( $col_widths, $align, $row );
        }
        
        $buf  = static::print_row( $col_widths, $align, $header );
        $buf .= static::print_divider_row( $col_widths, $align );
        foreach( $rows as $row ) {
            $row = static::obj_arr( $row );
            $buf .= static::print_row( $col_widths, $align, $row );
        }
        
        return $buf;
    }
    
    static protected function print_divider_row( $col_widths, $align) {
        $buf = '|';
        $idx = 0;
        foreach( $col_widths as $width ) {
            $rchar = $align[$idx] == 'right' ? ':' : '-';
            $buf .= '-' . str_pad( '-', $width, '-' ) . $rchar . "|";
            $idx ++;
        }
        $buf .= "\n";
        return $buf;
    }
    
    static protected function print_row( $col_widths, $align, $row ) {
        $buf = '|';
        $idx = 0;
        foreach( $row as $val ) {
            $pad_type = $align[$idx] == 'right' ? STR_PAD_LEFT : STR_PAD_RIGHT;
            $buf .= ' ' . str_pad( $val, $col_widths[$idx], ' ', $pad_type ) . " |";
            $idx ++;
        }
        return $buf . "\n";
    }

    static protected function calc_row_col_widths_and_align( &$col_widths, &$align, $row ) {
        $idx = 0;
        foreach( $row as $val ) {
            $len = strlen( $val );
            if( $len > @$col_widths[$idx] ) {
                $col_widths[$idx] = $len;
            }
            $align[$idx] = @$align[$idx] == 'right' ? 'right' : (static::is_numeric($val) ? 'right' : 'left');
            $idx ++;
        }
    }
    
    static protected function is_numeric($str) {
        return is_numeric($str) ||
                trim($str, 'x0..9A..Fa..f') == '';
    }
    
    static protected function obj_arr( $t ) {
       return is_object( $t ) ? get_object_vars( $t ) : $t;
    }
}
