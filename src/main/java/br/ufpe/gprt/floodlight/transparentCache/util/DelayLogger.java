package br.ufpe.gprt.floodlight.transparentCache.util;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

import br.ufpe.gprt.floodlight.transparentCache.properties.TCacheProperties;

public class DelayLogger implements Runnable {
	
	private StringBuffer buffer;

	public DelayLogger(){
		buffer = new StringBuffer();
		try {
			Files.deleteIfExists(Paths.get(TCacheProperties.getInstance().getDelaysLogFile()));
			Files.createFile(Paths.get(TCacheProperties.getInstance().getDelaysLogFile()));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Override
	public void run() {
		while(true){
			if(buffer.length() > 0){
				this.writeDataToLogFile();
			} else {
				try {
					synchronized (this) {
						this.wait(1000);	
					}
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
	}
	
	public synchronized void addDataToBuffer(String s){
		this.buffer.append(s+"\n");
	}
	
	public synchronized void writeDataToLogFile(){
		try {
		    Files.write(Paths.get(TCacheProperties.getInstance().getDelaysLogFile()), buffer.toString().getBytes() , StandardOpenOption.APPEND);

			buffer.setLength(0);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
