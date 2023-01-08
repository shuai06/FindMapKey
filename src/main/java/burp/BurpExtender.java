/**
 * 地图api key的检测
 */
package burp;

import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender, IHttpListener {
    //所有burp插件都必须实现IBurpExtender接口，而且实现的类必须叫做BurpExtender
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private PrintWriter stdout;
    private PrintWriter stderr;
    private String ExtenderName = "MapKeyFind";

    private List<String> mapKeyList = new ArrayList<>();


    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        //IBurpExtender必须实现的方法
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        callbacks.printOutput(ExtenderName);
        //stdout.println(ExtenderName);
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName(ExtenderName);
        callbacks.registerHttpListener(this); //如果没有注册，下面的processHttpMessage方法是不会生效的。处理请求和响应包的插件，这个应该是必要的

        mapKeyList.add("map.qq.com");
        mapKeyList.add("webapi.amap.com");
        mapKeyList.add("api.map.baidu.com");
        mapKeyList.add("maps.googleapis.com");
        mapKeyList.add("qqMapKey");
        mapKeyList.add("baidumap");
        mapKeyList.add("/wmts?tk=");
        mapKeyList.add("t0.tianditu.gov.cn");
        mapKeyList.add("api.tianditu.gov.cn/api");


    }

    @Override
    public void processHttpMessage(int toolFlag,boolean messageIsRequest,IHttpRequestResponse messageInfo){

        // messageIsRequest用于判断当前数据流量是 请求数据（Request）或者是 响应数据（Response）
        // messageInfo为IHttpRequestResponse接口的实例，可以通过messageInfo获取流量数据（包括请求数据及响应数据）的详细信息（包括请求的host、port、protocol、header（请求头）、body（请求包体）等）
        if (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY) {  //判断当前监听流量数据的模块是否为PROXY模块
            //不同的toolFlag代表了不同的burp组件 https://portswigger.net/burp/extender/api/constant-values.html#burp.IBurpExtenderCallbacks

//            if (messageIsRequest) { //对请求包进行处理
//                IRequestInfo analyzeRequest = helpers.analyzeRequest(messageInfo);  //对消息体进行解析,messageInfo是整个HTTP请求和响应消息体的总和，各种HTTP相关信息的获取都来自于它，HTTP流量的修改都是围绕它进行的。
//                /*****************获取参数**********************/
//                List<IParameter> paraList = analyzeRequest.getParameters();  //获取参数的方法
//                // 当body是json格式的时候，这个方法也可以正常获取到键值对；但是PARAM_JSON等格式不能通过updateParameter方法来更新。
//                // 如果在url中的参数的值是 key=json格式的字符串 这种形式的时候，getParameters应该是无法获取到最底层的键值对的。
//                for (IParameter para : paraList) {  // 循环获取参数，判断类型，进行加密处理后，再构造新的参数，合并到新的请求包中。
//                    String key = para.getName(); //获取参数的名称
//                    String value = para.getValue(); //获取参数的值
//                    int type = para.getType();
//                    stdout.println("参数 key value type: " + key + " " + value + " " + type);
//                }
            if (! messageIsRequest){ //只处理响应包
                try{
                    IRequestInfo analyzeRequest = helpers.analyzeRequest(messageInfo);
                    URL url = analyzeRequest.getUrl();
                    IResponseInfo analyzedResponse = helpers.analyzeResponse(messageInfo.getResponse()); //getResponse获得的是字节序列
                    //通过上面的analyzedResponseInfo得到响应数据的请求头列表
//                    List<String> headers = analyzedResponse.getHeaders(); //响应的http头
                    //得到完整的响应数据
                    String resp = new String(messageInfo.getResponse(), "UTF-8"); //响应整个包
                    short statusCode = analyzedResponse.getStatusCode();  //状态码
                    //通过上面的analyzedResponse得到响应数据包体（body）的起始偏移
                    int bodyOffset = analyzedResponse.getBodyOffset();// 响应包是没有参数的概念的，大多需要修改的内容都在body中
                    //根据响应数据的起始偏移 在 响应数据中得到响应数据包体（body）
                    String body = resp.substring(bodyOffset);
//                    stdout.println(body);

                    if (statusCode==200) {
                        //查找map的key等敏感信息
                        for(String s : mapKeyList){
                            if (body.contains(s)){
                                stdout.println("发现：" + s + "\t" + url.toString());

                            }
                        }
//                        //打印转换后的响应数据包体（body）内容
//                        stdout.println(body);
//                        //转换响应数据包体（body）内容为byte[]
//                        byte[] bodyByte = body.getBytes("UTF-8"); //将响应数据包体字符串转成byte数组
//                        //重新构建响应包体（body）数据 并发送到burp中
//                        //已经将响应数据包体（body）中的unicode编码转成中文
//                        messageInfo.setResponse(helpers.buildHttpMessage(headers, bodyByte));
                    }
                }catch(Exception e) {
                    stdout.println(e);
                }

            }


        }
    }








}