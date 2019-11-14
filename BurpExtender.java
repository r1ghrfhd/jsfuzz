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
		//ע�������
		pw.println("start js");
		m_callback.registerHttpListener(BurpExtender.this);
		file =new File("D:\\��͸���߳���\\weakpass\\fuzzDicts-master\\fuzzDicts-master\\js\\js.txt");
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
		/*Burp ����κ�һ�����߷��� HTTP 
		 ����ֻ���Ѽ������е�js�ļ�
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
			 * ��ȡ���һ��/.*.js���浽jsfuzz�ļ�
			 * ������ֱ���ڿ���̨��ӡ����������͸����
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
