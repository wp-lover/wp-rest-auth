<?php

namespace GSP;

class Authorization 
{

    private $UID;

    // this is the secret Key, please change it, and make it defficult to guess
    private $SecretKey = 'GSP';

    // Final encrypted Authorization Key
    public $userAuthKey;

    public $userAuthSavingStatus;

    function __construct()
    {

        if( array_key_exists( 'removeAuthKey', $_REQUEST ) && ! empty( $_REQUEST['removeAuthKey'] ) ) {
            if ($this->removeAuthKey( $_REQUEST['removeAuthKey'] )) {
               echo "User AuthKey removed";
            }else{
                echo "User AuthKey did not removed"; 
            }

            return;
        }
        

        if( array_key_exists( 'authKey', $_REQUEST ) && ! empty( $_REQUEST['authKey'] ) ){

            $this->checkUser();
           
           return;
        }

        if( array_key_exists( 'user-name', $_REQUEST ) && ! empty( $_REQUEST['user-pass'] ) ){

            // 
            $this->loginUserWithPassword();
        }
        

    } // __construct

    function checkUser()
    {
        $key = $_REQUEST['authKey'];

        $decoded = base64_decode($key);

       $jsonData = json_decode($decoded);

        if ( ! empty($jsonData->uid) && $data = $this->getAuthKey( $jsonData->uid )) {
            
           $decryptedData = json_decode($this->decryption( $data[0]['iv'], $data[0]['authKey'] ));

           if( $decryptedData ){
            echo var_dump($decryptedData);
            $this->UID = $decryptedData->uid;
            $this->setCurrentuser();

           }else{
            echo "invalid key";
           }
            
        }else{
            echo "did not get the key";
        }

    }

    function encryption ( $string )
    {
        $output = false;
        
        $encrypt_method = "AES-256-CBC";

        $randomSecret = $this->RandomLowerChar() . 'Isd$vsasskvnasd)3lsd3sdkfrKHDsw' . $this->RandomLowerChar();
        
        // hash
        $key = hash('sha256', $this->SecretKey);    
        
        // iv - encrypt method AES-256-CBC expects 16 bytes 
        $iv = substr(hash('sha256', $randomSecret ), 0, 16);
        
        $output = openssl_encrypt( $string , $encrypt_method, $key, 0, $iv );

        $this->setAuthKey( $iv, $output );


        
        $this->userAuthKey = base64_encode( json_encode([
            "encrypted_data" => $output,
            "uid" => $this->UID
        ]) ); 
       
        echo "iv: " . $iv . " key: " . $key . " " . $this->userAuthKey . " ,";

    }

    function decryption ( $iv, $encryptedString )
    {
        $output = false;
        
        $encrypt_method = "AES-256-CBC";

        // hash
        $key = hash('sha256', $this->SecretKey);    
        
        $output = openssl_decrypt( $encryptedString , $encrypt_method, $key, 0, $iv );
        
        return $output;
    }

    //  generate random english small latter
    function RandomLowerChar()
    {
        $characters = 'abcdefghijklmnopqrstuvwxyzaslfgl';
        
        $num = rand(0, 28);
    
        return $characters[$num];
    }  


    //  generate random english capital latter
    function RandomCapsChar()
    {
        $characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZLKHFFLS';
        
        $num = rand(0, 28);
    
        return $characters[$num];
    }

    // set user authorization key in the user_meta
    function setAuthKey( $iv, $encrypted)
    {
        $val = 
        [
            "iv" => $iv,
            "authKey" => $encrypted
        ];

        if (is_user_logged_in()) {
            echo " logged in user ";
        }else{
            echo " not logged in user ";
        }

        $update = update_user_meta( $this->UID , 'gspUserAuthKey', $val );

        // 
        echo $update;
        // if ( update_user_meta( $this->UID , 'gspUserAuthKey', $val , ' ' ) ) {
        //    echo "updated ";
        // }else{
        //     echo " did not updated ";
        // }
     }


    // get user-authorization key
    function getAuthKey( $uid )
    {
        if ( $data = get_user_meta( $uid, 'gspUserAuthKey' ) ) {
            return $data;     
        }

       return  false;
    }

    function removeAuthKey( $uid )
    {
        $uid = (int) $uid;
       if ( delete_user_meta( $uid , 'gspUserAuthKey' ) ) {
            return true;
       }

       return false;
    }


    function loginUserWithPassword() {
        $creds = array(
            'user_login'    => $_REQUEST['user-name'],
            'user_password' => $_REQUEST['user-pass'],
            'remember'      => true
        );
    
        $user = wp_signon( $creds, false );
    
        if ( is_wp_error( $user ) ) {
            $user->get_error_message();
            
            // user-did not logged-in
            return false;
        }

        $id = $user->data->ID;

        // set the user-ID in the UID property
        $this->UID = $user->data->ID;

        // echo var_dump( $user ); return;
        $this->userAuthKey = $this->encryption( json_encode([
            "uid" => $id,
            "userName" =>$user->data->user_login
        ]) );

        
    }

    function setCurrentuser()
    {
        
        wp_set_current_user($this->UID);

       $userData = get_user_by('ID' ,$this->UID);

       $this->userAuthKey = $this->encryption( json_encode([
        "uid" => $this->UID,
        "userName" =>$userData->userName
    ]) );

    }

}