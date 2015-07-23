package br.ufpe.gprt.floodlight.transparentCache;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;

import net.floodlightcontroller.core.IOFSwitch;

public class DummyHTTPClient implements Runnable {

	private Socket socks;
	private String host;
	private int port;
	private String request;
	private StringBuffer responseBuffer;
	private HttpMatcher httpMatcher;
	private IOFSwitch sw;
	
	public DummyHTTPClient(String host, int port, String request, HttpMatcher httpMatcher, IOFSwitch sw){
		this.host = host;
		this.port = port;
		this.request = request;
		this.httpMatcher = httpMatcher;
		this.sw = sw;
	}

	@Override
	public void run() {
		try {
			this.connect(host, port);
			
	        BufferedWriter out = new BufferedWriter(new OutputStreamWriter(this.socks.getOutputStream()));
	        out.write(request);
	        out.flush();
	        
	        BufferedReader in = new BufferedReader(new InputStreamReader(socks.getInputStream()));
	        
	        String line = in.readLine();
	        this.responseBuffer = new StringBuffer();

	        while(line != null){
	        	this.responseBuffer.append(line);
	        	line = in.readLine();
	        }
	        
	        this.disconnect();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		

		
	}
	
	private int connect(String host, int port) throws IOException {
		if(this.socks != null && this.socks.isConnected()){
			this.socks.close();
		}
		
		this.socks = new Socket();
		socks.connect(new InetSocketAddress(host, port));
		
		this.httpMatcher.addResponseFlowMod(sw, this.getLocalPort(), this.getLocalAddress());
		return this.socks.getLocalPort();
	}
	
	public void disconnect() throws IOException{
		if(this.socks != null){
			this.socks.close();
		}
	}
	
	public int getLocalPort() {
		return socks != null? socks.getLocalPort() : -1;
	}

	public InetAddress getLocalAddress() {
		return this.socks.getLocalAddress();
	}
	

}
