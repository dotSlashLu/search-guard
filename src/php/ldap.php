<?php
define('LDAP_HOST','ldap://localhost:389');
define('LDAP_EMAIL','@domain.com');

class CI_ldap {

    var $connect;

    function __construct() {
        $this->connect = ldap_connect(LDAP_HOST);
    }

    public function bind($username,$password){
        $username=str_replace(LDAP_EMAIL,'',$username);
        if($this->connect) {
            ldap_set_option($this->connect, LDAP_OPT_PROTOCOL_VERSION, 3);
            ldap_set_option($this->connect, LDAP_OPT_REFERRALS, 0 );
            $username.=LDAP_EMAIL;
            $bind = @ldap_bind($this->connect, $username, $password);
            ldap_close($this->connect);
            return $bind? 1: -2;
        }
        else {
            return -1;
        }
    }
    // 析构函数
    function __destruct(){
        if($this->connect){
            //ldap_close($this->connect);
        }
    }


    /**
     * 连接AD域获取用户的姓名和邮箱
     * @param $username
     * @param $password
     * @return array|bool = cn,displayname,mail
     */
    public function getUserInfo($username, $password)
    {
        $filterName=$username=str_replace(LDAP_EMAIL,'',$username);
        $username.=LDAP_EMAIL;
        $this->connect = ldap_connect(LDAP_HOST);
        ldap_set_option($this->connect, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($this->connect, LDAP_OPT_REFERRALS, 0);
        $bind = @ldap_bind($this->connect, $username, $password);
        if (!$bind) {
            echo json_encode(array(
                "status" => -1
            ));
            return ;
        }
        if ($bind) {
            $base_dn = "DC=meizu,DC=com";//定义要进行查询的目录主键
            $filter_col = "cn";//定义用于查询的列
            $filter_val = $filterName;//定义用于匹配的值
            $filter = array('mail', 'displayName', 'cn');
            $result = ldap_search($this->connect, $base_dn, "($filter_col=$filter_val)", $filter);//执行查询
            //echo "Error message: ".ldap_error($this->connect)."<br>";
            $entry = ldap_get_entries($this->connect, $result);//获得查询结果
            if ($entry["count"] > 0) {
                $entry = $entry[0];
                foreach ($entry as $k => $v) {
                    if (is_numeric($k))
                        unset($entry[$k]);

                    elseif(is_array($v))
                        $entry[$k] = $v[0];
                }
                unset($entry["count"]);
            }
            $entry["status"] = 0;
            echo json_encode($entry);
            //var_dump($entry);//输出查询结果
            ldap_close($this->connect);
        } else {
            //die("Can't bind to LDAP server.");
            echo json_encode(array(
                "status" => -1
            ));
            return false;
        }
    }
}

if (isset($_GET["name"]) && isset($_GET["passwd"])) {
    $LDAP = new CI_ldap();
    $username = $_GET["name"];
    $password = $_GET["passwd"];
    $LDAP->getUserInfo($username, $password);
    unset($LDAP);
}

