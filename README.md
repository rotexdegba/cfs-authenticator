### Cfs Authenticator 

This package extends auraphp/Aura.Auth (https://github.com/auraphp/Aura.Auth) by adding a custom LDAP adapter for the NRCan's LDAP / Active Directory setup.

### Demo Code:

```php
<?php
    require_once './vendor/autoload.php';

    function ebr($var) {

        echo $var.'<br>'; 
    }

    function eprebr($var) {

        if( is_array($var) ) {

            $var = print_r($var, true); 
        }

        echo "<pre>$var</pre>";
    }

    function dumpAuthinfo($auth) {

        ebr($auth->getFirstActive());
        ebr($auth->getLastActive());
        ebr($auth->getStatus());
        ebr($auth->getUserName());
        eprebr($auth->getUserData());
    }

    //session_save_path('/var/www/html/rotimi/cfs-authenticator/ignore/');
    $auth_factory = new \Aura\Auth\AuthFactory($_COOKIE);
    $auth = $auth_factory->newInstance();

    $server = 'ldap.server.org.ca';
    $dnformat = 'ou=Company Name,dc=Department Name,cn=users';
    $cfs_ldap_adapter_specific_params = array(
        'filter'                        => '\w',
        'basedn'                        => 'DC=yada,DC=yada,DC=yada,DC=yada',
        'bindpw'                        => 'Pa$$w0rd',
        'limit'                         => array('dn'),
        'searchfilter'                  => 'somefilter',
        'successful_login_callback' 	=> function($login_timestamp_string) {
                                                echo $login_timestamp_string.'<br>';
                                           }
    );

    $custom_adapter = new \Cfs\Authenticator\Adapter\CfsLdapAdapter(
                                new \Aura\Auth\Phpfunc(),
                                $server, 
                                $dnformat,
                                array(), 
                                $cfs_ldap_adapter_specific_params
                            );

    $login_service = $auth_factory->newLoginService($custom_adapter);
    $logout_service = $auth_factory->newLogoutService($custom_adapter);
    $resume_service = $auth_factory->newResumeService($custom_adapter);

    ////////////////////////////////////////////////////////////////////
    // LOGIN SERVICE DEMO
    ////////////////////////////////////////////////////////////////////
    try {

        $login_service->login($auth, array(
            'username' => 'a_username',
            'password' => 'a_password'
        ));
        ebr( "You are now logged into a new session.");
        dumpAuthinfo($auth);

    } catch (\Aura\Auth\Exception\UsernameMissing $e) {

        ebr("The 'username' field is missing or empty.");
        throw new \Exception();

    } catch (\Aura\Auth\Exception\PasswordMissing $e) {

        ebr("The 'password' field is missing or empty.");
        throw new \Exception();

    } catch (\Aura\Auth\Exception\UsernameNotFound $e) {

        ebr("The username you entered was not found.");
        throw new \Exception();

    } catch (\Aura\Auth\Exception\MultipleMatches $e) {

        ebr("There is more than one account with that username.");
        throw new \Exception();

    } catch (\Aura\Auth\Exception\PasswordIncorrect $e) {

        ebr("The password you entered was incorrect.");
        throw new \Exception();

    } catch (\Aura\Auth\Exception\ConnectionFailed $e) {

        ebr("Cound not connect to IMAP or LDAP server.");
        ebr("This could be because the username or password was wrong,");
        ebr("or because the the connect operation itself failed in some way. ");
        ebr($e->getMessage());
        throw new \Exception();

    } catch (\Aura\Auth\Exception\BindFailed $e) {

        ebr("Cound not bind to LDAP server.");
        ebr("This could be because the username or password was wrong,");
        ebr("or because the the bind operation itself failed in some way. ");
        ebr($e->getMessage());
        throw new \Exception();

    } catch (\Exception $e) {

        echo "Invalid login details. Please try again.";
    }

    ////////////////////////////////////////////////////////////////////
    // RESUME SERVICE DEMO
    ////////////////////////////////////////////////////////////////////
    sleep(3);//sleep for 3 seconds
    $resume_service->resume($auth);

    ebr('');//print line break

    switch (true) {
        case $auth->isAnon():
            echo "You are not logged in.";
            break;
        case $auth->isIdle():
            echo "Your session was idle for too long. Please log in again.";
            break;
        case $auth->isExpired():
            echo "Your session has expired. Please log in again.";
            break;
        case $auth->isValid():
            echo "You are still logged in.";
            break;
        default:
            echo "You have an unknown status.";
            break;
    }

    ebr('');//print line break
    dumpAuthinfo($auth);

    ////////////////////////////////////////////////////////////////////
    // LOGOUT SERVICE DEMO
    ////////////////////////////////////////////////////////////////////
    $logout_service->logout($auth);

    ebr('');//print line break

    if ($auth->isAnon()) {

        echo "You are now logged out.";

    } else {

        echo "Something went wrong; you are still logged in.";
    }

    ebr('');//print line break
    dumpAuthinfo($auth);
?>
```

See https://github.com/auraphp/Aura.Auth/blob/2.x/README.md for more examples on how to use this package.