package br.ufpe.gprt.floodlight.transparentCache;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.InetSocketAddress;
import java.net.Socket;

public class DummyHTTPClient {

	private Socket socks;

	public int connect(String host, int port) throws IOException {
		if(this.socks != null && this.socks.isConnected()){
			this.socks.close();
		}
		
		this.socks = new Socket();
		socks.connect(new InetSocketAddress(host, 80));
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
	
	public void sendRequest(String request) throws IOException{
		if(this.socks == null || !this.socks.isConnected()){
			throw new IOException("Client not connected, therefore, it is impossible to send requests. Connect this client first!");
		}

        BufferedWriter out = new BufferedWriter(new OutputStreamWriter(this.socks.getOutputStream()));
        out.write(request);
        out.flush();
        
	}

}
