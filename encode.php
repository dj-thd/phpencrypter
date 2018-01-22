<?php

// Usage: php -f encode.php <input php file> <output php encoded file>

// To execute the encrypted payload, you will need to use the provided
// key in a cookie named "k", i.e. $_COOKIE['k'] = "(provided key)"

// RC4 function
function rc4($key, $str) {
	$s = array();
	for ($i = 0; $i < 256; $i++) {
		$s[$i] = $i;
	}
	$j = 0;
	for ($i = 0; $i < 256; $i++) {
		$j = ($j + $s[$i] + ord($key[$i % strlen($key)])) % 256;
		$x = $s[$i];
		$s[$i] = $s[$j];
		$s[$j] = $x;
	}
	$i = 0;
	$j = 0;
	$res = '';
	for ($y = 0; $y < strlen($str); $y++) {
		$i = ($i + 1) % 256;
		$j = ($j + $s[$i]) % 256;
		$x = $s[$i];
		$s[$i] = $s[$j];
		$s[$j] = $x;
		$res .= $str[$y] ^ chr($s[($s[$i] + $s[$j]) % 256]);
	}
	return $res;
}

if(!isset($argv[1]) || !isset($argv[2])) {
	fputs(STDERR, "Usage: $argv[0] <input php file> <output encoded file>\n\n");
	die();
}

// Get original payload file contents
$file_data = php_strip_whitespace($argv[1]);

// Remove starting <?php block
$regex = '/^\s*<\?php\s+(.*)/i';
if(preg_match($regex, $file_data)) {
        $file_data = preg_replace($regex, '\1', $file_data);
}

// Compress the payload
$file_data = gzencode($file_data, 9);

// Generate key
$key = md5(random_bytes(32));

// Encrypt payload with rc4
$d = rc4(hex2bin($key), $file_data);

// Encode payload with base85 (input = $d, output = $o)
$o='';$s='strlen';$t='substr';$u='unpack';$v='pow';$w='chr';$l=$s($d);for($i=0;$i<$l;$i+=4){$c=$t($d,$i,4);if($s($c)<4)break;$b=$u('N',$c);$b=$b[1];if($b==0){$o.='z';continue;}for($j=4;$j>=0;$j--){$p=$v(85,$j);$o.=$w((int)(($b/$p)+33));$b%=$p;}}if($i<$l){$n=$l-$i;$c=$t($d,-$n);for($j=$n;$j<4;$j++)$c.="\0";$b=$u('N',$c);$b=$b[1];for($j=4;$j>=(4-$n);$j--){$p=$v(85,$j);$o.=$w((int)(($b/$p)+33));$b%=$p;}}

// Prepare payload to be inserted into PHP string
$d = str_replace("'", "\\'", str_replace("\\", "\\\\", $o));

// Get decrypter, put payload into appropiate place
$d = str_replace('{***}', $d, file_get_contents('decoder.inc'));

// Output decrypter+payload to the output file
file_put_contents($argv[2], $d);

// Output the key to stdout
printf("Done, the encryption key is %s\n", $key);
