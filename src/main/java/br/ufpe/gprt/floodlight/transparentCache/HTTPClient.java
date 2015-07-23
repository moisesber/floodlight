package br.ufpe.gprt.floodlight.transparentCache;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URISyntaxException;
import java.net.URL;

public class HTTPClient {
	
	  public static void main(String[] args) throws IOException, URISyntaxException {
	        URL oracle = new URL("http://www.oracle.com/");
	        
	        oracle.toString();
	        
//	        URLConnection yc = oracle.openConnection();
//	        
//	        BufferedReader in = new BufferedReader(new InputStreamReader(
//	                                    yc.getInputStream()));
//	        String inputLine;
//	        while ((inputLine = in.readLine()) != null) 
//	            System.out.println(inputLine);
//	        in.close();
	        
//	        System.out.println(Unirest.post("http://httpbin.org/post")
//	        .queryString("name", "Mark")
//	        .field("last", "Polo")
//	        .asString().getBody().intern());
	        
	        Socket socks = new Socket();
	        String host = "10.0.0.254";
	        socks.connect(new InetSocketAddress(host, 80) );
	        
	        System.out.println("Local port is "+socks.getLocalPort());
	        
	        BufferedWriter out = new BufferedWriter(new OutputStreamWriter(socks.getOutputStream()));
	        String request = "GET /video.mp4?tag=java HTTP/1.1 \n"
	        		+ "host: " + host +"\n"
	        		+ "User-Agent: dummyclient/0.1\n\n";
	        
	        out.write(request);
	        out.flush();
//	        socks.close();
	        BufferedReader in = new BufferedReader(new InputStreamReader(socks.getInputStream()));
	        
//	        BufferedReader in = new BufferedReader(new InputStreamReader(Unirest.post("http://httpbin.org/post")
//	        		.queryString("name", "Mark")
//	        		.field("last", "Polo").getHttpRequest().getBody().getEntity().getContent()));
	        String test = in.readLine();
    
	        while(test != null){
	        	System.out.println(test);
	        	test = in.readLine();
	        }
//	        
	        socks.close();
//	        System.out.println(Unirest.get("http://httpbin.org/post")
//	        .queryString("name", "Mark").getHttpRequest());
//	        .field("last", "Polo")
//	        .asString().getBody().intern());
	        
	        
	        
//	        BufferedReader in = new BufferedReader(new InputStreamReader(Unirest.post("http://httpbin.org/post")
//	    	        .queryString("name", "Mark")
//	    	        .field("last", "Polo").getHttpRequest().getBody().getEntity().getContent()));
//	        String test = in.readLine();
	        
//	        while(test != null){
//		        System.out.println(test);
//		        test = in.readLine();
//	        }
	        
//	        String test = Unirest.post("http://httpbin.org/post")
//	        .queryString("name", "Mark")
//	        .field("last", "Polo").getHttpRequest().getBody().getEntity().getContent();
	        

//	        .asString();
		  }

}
