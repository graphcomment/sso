<?php

define('GC_SECRET', '123456');
define('GC_PUBLIC', 'abcdef');

$data = array(
        "id" => $user["id"], // required unique
        "username" => $user["username"],// required unique
        "email" => $user["email"],// required unique
        "bio" => $user["bio"],// (optionnal) description
        "picture" => $user["picture"]// (optionnal) full url only
    );

function gc_hmacsha1($data, $key) {
    $blocksize=64;
    $hashfunc='sha1';
    if (strlen($key)>$blocksize)
        $key=pack('H*', $hashfunc($key));
    $key=str_pad($key,$blocksize,chr(0x00));
    $ipad=str_repeat(chr(0x36),$blocksize);
    $opad=str_repeat(chr(0x5c),$blocksize);
    $hmac = pack(
                'H*',$hashfunc(
                    ($key^$opad).pack(
                        'H*',$hashfunc(
                            ($key^$ipad).$data
                        )
                    )
                )
            );
    return bin2hex($hmac);
}

$message = base64_encode(json_encode($data));
$timestamp = time();
$hmac = gc_hmacsha1($message . ' ' . $timestamp, GC_SECRET);
?>

<script type="text/javascript">
var gc_config = function() {
    this.page.auth = "<?php echo "$message $hmac $timestamp"; ?>";
    this.page.pubKey = "<?php echo GC_PUBLIC; ?>";
}
</script>