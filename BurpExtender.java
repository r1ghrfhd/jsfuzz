package burp;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BurpExtender implements IBurpExtender,IHttpListener,IExtensionStateListener{
	IBurpExtenderCallbacks m_callback;
	IExtensionHelpers helpers;
    PrintWriter pw;
    File file;
    FileOutputStream fos;
	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		this.m_callback = callbacks;
		helpers = callbacks.getHelpers();
		pw=new PrintWriter(m_callback.getStdout(),true);
		m_callback.setExtensionName("collection_js_file");
		//注册监听器
		pw.println("start js");
		m_callback.registerHttpListener(BurpExtender.this);
		file =new File("D:\\渗透工具常用\\weakpass\\fuzzDicts-master\\fuzzDicts-master\\js\\js.txt");
		if(!file.exists()){
			try {
				file.createNewFile();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		try {
			fos = new FileOutputStream(file);
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
		/*Burp 里的任何一个工具发起 HTTP 
		 这里只是搜集请求中的js文件
		*/
		if(messageIsRequest){
		try{
		String urlPath= helpers.analyzeRequest(messageInfo).getUrl().getPath();
		String regex = "/(.*?\\.js)$";
		Pattern compile = Pattern.compile(regex);
		Matcher matcher = compile.matcher(urlPath);
		if(matcher.find()){
			String jspath = matcher.group();
			/*js/syntaxhighlighter_3.0.83/scripts/shBrushJScript.js
			 * 截取最后一个/.*.js保存到jsfuzz文件
			 * 其他的直接在控制台打印出来便于渗透测试
		*/	
			String newjs=jspath.substring(jspath.lastIndexOf("/"));
			pw.println(jspath);
			fos.write(newjs.getBytes());
			fos.write("\n".getBytes());
		}
		}
		catch (Exception e) {
			// TODO: handle exception
		}
		}
		
	}
    
	/**/
	@Override
	public void extensionUnloaded() {
		
		try {
			fos.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

}
