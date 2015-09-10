<?php
namespace Cfs\Authenticator\Adapter;

/**
 * Description of CfsLdapAdapter
 *
 * @author aadegbam
 */
class CfsLdapAdapter extends \Aura\Auth\Adapter\LdapAdapter
{
    ////////////////////////////////////////////////////////////////////////////
    // \Aura\Auth\Adapter\LdapAdapter protected properties redefined here for
    // clarity (reduce the need to keep going back and forth between the code 
    // for this class and its parent class (\Aura\Auth\Adapter\LdapAdapter) ).
    ////////////////////////////////////////////////////////////////////////////
    
    /**
     *
     * An LDAP server connection string.
     *
     * @var string
     *
     */
    protected $server;
    
    /**
     *
     * An sprintf() format string for the LDAP query.
     *
     * @var string
     *
     */
    protected $dnformat = null;
    
    /**
     *
     * Set these options after the LDAP connection.
     *
     * @var array
     *
     */
    protected $options = array(
                            LDAP_OPT_PROTOCOL_VERSION=>3 ,
                            LDAP_OPT_REFERRALS=>0
                         );
    
    ////////////////////////////////////////////////////////////////////////////
    // CfsLdapAdapter specific properties.
    ////////////////////////////////////////////////////////////////////////////
    
    /**
     *
     * A regular-expression snippet that lists allowed characters in the username.  
     * This is to help prevent LDAP injections. 
     * Default expression is '\w' (that is, only word characters are allowed).
     * 
     * @var string 
     * 
     */
    protected $filter = '\w';
    
    /**
     *
     * Password to bind with when searching for the DN entry for a specified username.
     * This is different from the password associated with the user we are trying to
     * authenticate.
     * 
     * @var string
     * 
     */
    protected $bindpw = ''; // this changes every couple of moths should be supplied during instantiation
    
    /**
     *
     * Search for the dn using this as the base.
     * 
     * @var string
     * 
     */
    protected $basedn = '';
    
    /**
     *
     * Limit search results to these.
     * 
     * @var array
     * 
     */
    protected $limit = array('dn');
    
    /**
     *
     * Search for a user's dn where `searchfilter`=$username 
     * ($username is the username of the user we are trying to authenticate).
     * 
     * @var string
     * 
     */
    protected $searchfilter = '';
    
    /**
     * 
     * The a function which accepts one string as parameter.
     * This function will be invoked when $this->bind($conn, $username, $password)
     * succeeds. A string containing the exact time the bind (or should we say
     * the LDAP login) succeeded and the associated username that was just
     * successfully authenticated.
     * 
     * @var callable
     */
    protected $successful_login_callback = null;


    public function __construct(
        \Aura\Auth\Phpfunc $phpfunc, $server, $dnformat, 
        array $ldap_options = array(), array $class_property_vals = array()
    ) {
        if( empty($ldap_options) || count($ldap_options) <= 0 ) {
        
            //use default array
            $ldap_options = $this->options;
        }
        
        parent::__construct($phpfunc, $server, $dnformat, $ldap_options);
        
        if(count($class_property_vals) > 0) {
            
            //set properties of this class specified in $extra_opts
            foreach($class_property_vals as $property_name => $property_value) {
  
                if ( property_exists($this, $property_name) ) {
                    
                    $this->$property_name = $property_value;

                } elseif ( property_exists($this, '_'.$property_name) ) {

                    $this->{"_$property_name"} = $property_value;
                }
            }
        }
    }
    
    /**
     *
     * Binds to the LDAP server with username and password.
     *
     * @param resource $conn The LDAP connection.
     *
     * @param string $username The input username.
     *
     * @param string $password The input password.
     *
     * @throws Exception\BindFailed when the username/password fails.
     *
     */
    protected function bind($conn, $username, $password)
    {       
        if(empty($this->bindpw) || empty($this->basedn) || empty($this->searchfilter)) {
            
            //use the parent bind method instead
            //not enough parameters supplied to execute 
            //custom logic for CFS LDAP authentication
            parent::bind($conn, $username, $password);
            return;
        }
        
        //This is now being handled by $this->connect() using $this->options
        //upgrade to LDAP3 when possible
        //@ldap_set_option($conn, LDAP_OPT_PROTOCOL_VERSION, 3);
        
        //This is now being handled by $this->connect() using $this->options
        //Referrals = 0
        //@ldap_set_option($conn, LDAP_OPT_REFERRALS, 0);
        
        // filter the handle to prevent LDAP injection
        $lcase_username = strtolower($this->escape($username));
        
        /** 
         * Before we can authenticate the user, we need to get the 
         * user's dn. This varies across the organization
         * 
         */
        $rdn = $this->_getDn($conn, $lcase_username);
        
        if (!$rdn) {

            $msg = 'No LDAP DN entries found in '
                 . get_class($this).'::'.__FUNCTION__.'(...)'
                 . " for username: '$lcase_username'";
            $this->throwLdapOperationException($conn, $msg);
            //return false;
        }
		
        // bind to the server
        $bind = $this->phpfunc->ldap_bind($conn, $rdn, $password);
        
        // did the bind succeed?
        if ($bind) {
            
            $func = $this->successful_login_callback;
            
            if( is_callable($func) ) {
                
                $class = get_class($this).'::'.__FUNCTION__.'(...)';
                $msg = "User '$username' logged in on ".date("l, F jS Y H:i:s A");
                $func( "{$class}: {$msg}" );
            }
            
            ldap_close($conn);
            return true;
            
        } else {
            
            $this->throwLdapOperationException($conn);
        }
    }

    /**
     *
     * Gets the DN of the 1st entry returned by the call to ldap_get_entries() in this method
     *
     * @param resource $conn An LDAP link identifier, returned by ldap_connect()
     * 
     * @param string $username The input username.
     *
     * @return string DN of the 1st entry returned by the call to ldap_get_entries() in this method
     *
     */
    protected function _getDn($conn, $username)
    {
        $r = $this->phpfunc->ldap_bind($conn, $this->dnformat, $this->bindpw);
        
        if ( !$r ) {
            
            $this->throwLdapOperationException($conn, '');
        }

        // Now search for the user
        $srchfiltr = "{$this->searchfilter}=$username";
        $srch_res = $this->phpfunc
                         ->ldap_search($conn, $this->basedn, $srchfiltr, $this->limit);

        if (!$srch_res) {
            
            $msg = 'LDAP search failed in '.get_class($this).'::'.__FUNCTION__.'(...)'
                 . " with basedn:'{$this->basedn}' and dnformat:'{$this->dnformat}'";
            $this->throwLdapOperationException($conn, $msg);
        }

        /**
         * Look for entries based on search.
         */
        $entries = $this->phpfunc->ldap_get_entries($conn, $srch_res);

        if ( !$entries ) {
            
            //return false;
            $msg = 'No LDAP DN entries found in '.get_class($this).'::'.__FUNCTION__.'(...)'
                 . ' with search result:'. var_export($srch_res, true);
            $this->throwLdapOperationException($conn, $msg);
        }
        
        if ($entries['count'] > 0) {
            
            //return the DN of the 1st entry returned by the call to ldap_get_entries()
            return $entries[0]['dn'];
        }
        
        return false;
    }
    
    protected function escape($str) {
        
        $escaped_str = parent::escape($str);
        
        $regex = '//';//empty regular expression
        
        if( !empty($this->filter) ) {
            
            $regex = '/[^' . $this->filter . ']/'; //Matches non-word characters.
        }
        
        //Try to strip out all non-word characters and return sanitized string.
        return preg_replace($regex, '', $escaped_str);
    }
    
    protected function throwLdapOperationException($conn, $more_info='') {
        
        $error = $this->phpfunc->ldap_errno($conn)
               . ': '
               . $this->phpfunc->ldap_error($conn). ': ' . $more_info
               . PHP_EOL . 'LDAP OBJECT:' .PHP_EOL. var_export($this, true);

        $this->phpfunc->ldap_close($conn);

        throw new \Aura\Auth\Exception\BindFailed($error);
    }
}