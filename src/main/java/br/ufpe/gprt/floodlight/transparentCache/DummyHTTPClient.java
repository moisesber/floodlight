package br.ufpe.gprt.floodlight.transparentCache;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.TransportPort;

import br.ufpe.gprt.floodlight.tcpsplicing.ClientTCPSplicingInfo;
import net.floodlightcontroller.core.IOFSwitch;

public class DummyHTTPClient implements Runnable {

	private Socket socks;
	private String host;
	private int port;
	private String request;
	private StringBuffer responseBuffer;
	private HttpTransparentCache httpMatcher;
	private IPv4Address sourceAddress;
	private int sourcePort;
	private IPv4Address destinationAddress;
	private int destinationPort;
	
	public DummyHTTPClient(String host, int port, String request, HttpTransparentCache httpTransparentCache, IPv4Address sourceAddress,
			int sourcePort, IPv4Address destinationAddress, int destinationPort){
		this.host = host;
		this.port = port;
		this.request = request;
		this.httpMatcher = httpTransparentCache;
		this.sourceAddress = sourceAddress;
		this.sourcePort = sourcePort;
		this.destinationAddress = destinationAddress;
		this.destinationPort = destinationPort;
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
		
//		//Useless code, this traffic will be over GTP tunnels
//		this.httpMatcher.addDestinationFlowModToController(sw, this.getLocalPort(), this.getLocalAddress());
		this.httpMatcher.addConnectedDummyClient(this.getLocalPort(), this);
		return this.socks.getLocalPort();
	}
	
	public void disconnect() throws IOException{
		if(this.socks != null){
			this.socks.close();
			this.httpMatcher.delConnectedDummyClient(this.getLocalPort());
		}
	}
	
	public int getLocalPort() {
		return socks != null? socks.getLocalPort() : -1;
	}

	public InetAddress getLocalAddress() {
		return this.socks.getLocalAddress();
	}

	public IPv4Address getSourceAddress() {
		return sourceAddress;
	}

	public int getSourcePort() {
		return sourcePort;
	}
	
	public String toString(){
		return "DummyClient: localPort="+this.getLocalPort()+ " sourceAddr="+this.sourceAddress+" srcPort="+this.sourcePort;
	}

	public IPv4Address getDestinationAddress() {
		return destinationAddress;
	}

	public int getDestinationPort() {
		return destinationPort;
	}
	
}
