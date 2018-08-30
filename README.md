# BaiduSms
百度云 sms php版本

官方没有给出php版本的短信发送sdk, 在此借鉴 http://www.thinkindrupal.com/node/5983 文章，并在此基础上将方法改成 `单例模式` 在原来的基础上更加容易调用

- 1.打开 `BaiduSms.php ` 修改 sms函数中 `accessKey 、 secretAccessKey` 这两个参数登录百度云账号，在右上角头像的`安全认证`中可以获得

  如果发送模板固定，可以修改 init_array 中的 `invokeId、templateCode`,这样以后调用时，就无需在传这两个参数。
  
- 2.修改命名空间，修改第二行的namespace,修改成为自己的目录。（laravel为例，我是放在 `app/Http/Library` 下）

- 3.调用
  ```
  $to = [
      //"invokeId" => "", //如果在类中已经设定好，则此处无需再写
      //"templateCode" => "", //如果在类中已经设定好，则此处无需再写
      "phoneNumber" => "188********",
      "contentVar" => [
          "code" => str_shuffle(rand(100000,999999))  //模板里面的变量
      ]
  ];
   $re = BaiduSms::sms($to);//发送
   //var_dump($re); //打印返回结果 
   
   /**********打印结果START************/
   object(stdClass)#869 (3) {
        ["code"]=>
        string(4) "1000"
        ["message"]=>
        string(6) "成功"
        ["requestId"]=>
        string(36) "9b2fbcca-6da9-4bfc-a458-93a676dcbb48"
    }
   /**********打印结果END************/
  ```
- 4.sms函数接收两个数组参数 ，一个是发送的数据的数组，一个是初始化`endPoint、accessKey、secretAccessKey`的数组，如果不想在类中固定初始化的`key`,则传入第二个参数即可。例：BaiduSms::sms($to,$config)
