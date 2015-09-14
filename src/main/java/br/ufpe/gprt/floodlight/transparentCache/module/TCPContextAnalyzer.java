package br.ufpe.gprt.floodlight.transparentCache.module;

import java.nio.ByteBuffer;
import java.util.Random;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;

import org.projectfloodlight.openflow.types.IpProtocol;
import org.slf4j.LoggerFactory;

public class TCPContextAnalyzer {
	
	public static final short ACK_FLAG = (short)0x010;

	public static final short FIN_ACK_FLAG = (short)0x011;
	
	public static final short FIN_PSH_ACK_FLAG = (short)0x019;
	
	public static final short RST_FLAG = (short)0x004;
	
	public static final short SYN_FLAG = (short)0x002;
	
	public static final short SYN_ACK_FLAG = (short)0x012;
	
	
	private byte[] ackOptionsHeader = new byte[] {
			(byte) 0x01, (byte) 0x01,
			(byte) 0x08, (byte) 0x0a, 
//			(byte) 0x00, (byte) 0x64, (byte) 0xf2, (byte) 0xae, 
//			(byte) 0x00, (byte) 0x5a, (byte) 0x2c, (byte) 0x6e
	};
	
	
	
	public boolean checkIfACKReceived(TCP tcp){
		return tcp.getFlags() == ACK_FLAG;
	}
	
	public boolean checkIfSYNReceived(TCP tcp){
		return tcp.getFlags() == SYN_FLAG;
	}
	
	public boolean checkIfSYNACKReceived(TCP tcp){
		return tcp.getFlags() == SYN_ACK_FLAG;
	}
	
	public boolean checkIfFINACKReceived(TCP tcp){
		return tcp.getFlags() == FIN_ACK_FLAG;
	}
	
	public boolean checkIfRSTReceived(TCP tcp) {
		return tcp.getFlags() == RST_FLAG;
	}
	
	public boolean checkIfFINPSHACKReceived(TCP tcp){
		return tcp.getFlags() == FIN_PSH_ACK_FLAG;
	}
	
	public TCP getACKFromSYNACK(TCP synACK){
		TCP clone = (TCP)synACK.clone();
		
		clone.setDestinationPort(synACK.getSourcePort());
		clone.setSourcePort(synACK.getDestinationPort());
		clone.setAcknowledge(synACK.getSequence() + 1);
		clone.setSequence(synACK.getAcknowledge());
		clone.setOptions(getAckOptions(synACK.getOptions()));
		clone.setFlags(ACK_FLAG);
		clone.resetChecksum();
		
		return clone;
	}
	
	public int[] getTsValues(TCP tcp){
        ByteBuffer bb = ByteBuffer.wrap(tcp.getOptions());
        int tsVal = -1;
        int tsecr = -1;
        
        while(bb.hasRemaining()){
        	byte kind = bb.get();
        	
        	if(kind != 1){
            	byte length = bb.get();
            	
            	if(kind != 8){
            		for (int i = 0; i < length -2 ; i++) {
    					bb.get();
    				}
            	} else {
            		tsVal = bb.getInt();
            		tsecr = bb.getInt();
            	}
        	}
        }
        
        return new int[] { tsVal, tsecr };
	}
	
	private byte[] getAckOptions(byte[] options) {
		
        ByteBuffer bb = ByteBuffer.wrap(options);
        int tsVal = -1;
        int tsecr = -1;
        
        while(bb.hasRemaining()){
        	byte kind = bb.get();
        	
        	if(kind != 1){
            	byte length = bb.get();
            	
            	if(kind != 8){
            		for (int i = 0; i < length -2 ; i++) {
    					bb.get();
    				}
            	} else {
            		tsVal = bb.getInt();
            		tsecr = bb.getInt();
            	}
        	}
        }
		
		byte[] newOptions = new byte[12];
		
        ByteBuffer newbb = ByteBuffer.wrap(newOptions);
        
        for (int i = 0; i < ackOptionsHeader.length; i++) {
        	newbb.put(ackOptionsHeader[i]);
		}
        int temp = tsVal;
        tsVal = tsecr + 1;
        tsecr = temp;
        newbb.putInt(tsVal);
        newbb.putInt(tsecr);

        return newOptions;
	}
	
	public TCP getACKFromTCPData(TCP data){
		TCP clone = (TCP)data.clone();
		byte[] payloadData = ((Data)data.getPayload()).getData();
		
		clone.setDestinationPort(data.getSourcePort());
		clone.setSourcePort(data.getDestinationPort());
		clone.setAcknowledge(data.getSequence() + payloadData.length);
		clone.setSequence(data.getAcknowledge());
		clone.setOptions(getFINACKOptions(data.getOptions()));
		clone.setFlags(ACK_FLAG);
		clone.setPayload(new Data(new byte[0]));
		clone.resetChecksum();
		
		return clone;
	}
	
	public TCP getFINACKFromFINACK(TCP finACK){
		TCP clone = (TCP)finACK.clone();
		
		clone.setDestinationPort(finACK.getSourcePort());
		clone.setSourcePort(finACK.getDestinationPort());
		clone.setAcknowledge(finACK.getSequence() + 1);
		clone.setSequence(finACK.getAcknowledge());
		clone.setOptions(getFINACKOptions(finACK.getOptions()));
		clone.resetChecksum();
		return clone;
	}
	
	private byte[] getFINACKOptions(byte[] options) {
        ByteBuffer bb = ByteBuffer.wrap(options);
        byte[] synDataOptions = new byte[options.length];
        ByteBuffer synbb = ByteBuffer.wrap(synDataOptions);
        
        while(bb.hasRemaining()){
        	byte kind = bb.get();
        	synbb.put(kind);
        	
        	if(kind != 1){
            	byte length = bb.get();
            	synbb.put(length);
            	
            	if(kind != 8){
            		for (int i = 0; i < length -2 ; i++) {
    					synbb.put(bb.get());
    				}
            	} else {
            		int tsVal = bb.getInt();
            		int tsecr = bb.getInt();
            		
            		synbb.putInt(tsecr + 1);
            		synbb.putInt(tsVal);
            	}
        	}
        }
        
        return synDataOptions;
	}
	
	private byte[] getSYNACKOptions(byte[] options) {
        ByteBuffer bb = ByteBuffer.wrap(options);
        byte[] synDataOptions = new byte[options.length];
        ByteBuffer synbb = ByteBuffer.wrap(synDataOptions);
        
        while(bb.hasRemaining()){
        	byte kind = bb.get();
        	synbb.put(kind);
        	
        	if(kind != 1){
            	byte length = bb.get();
            	synbb.put(length);
            	
            	if(kind != 8){
            		for (int i = 0; i < length -2 ; i++) {
    					synbb.put(bb.get());
    				}
            	} else {
            		int tsVal = bb.getInt();
            		int tsecr = bb.getInt();
            		
            		synbb.putInt(Math.abs((int)System.currentTimeMillis()));
            		synbb.putInt(tsVal);
            	}
        	}
        }
        
        return synDataOptions;
	}

	public TCP getSYNFromTCPGet(TCP get, int cachePort) {
		TCP syn = new TCP();
		syn.setSequence(get.getSequence() - 1);
		syn.setAcknowledge(0);
		syn.setFlags(SYN_FLAG);
		syn.setWindowSize((short)29200);
		syn.setOptions(getSYNOptions(get.getOptions()));
		syn.setPayload(new Data(new byte[0]));
		syn.setSourcePort(get.getSourcePort());
		syn.setDestinationPort(cachePort);
		
		syn.resetChecksum();
		
		return syn;
	}
	
	
	
	private byte[] getSYNOptions(byte[] getOptions) {
		
        ByteBuffer bb = ByteBuffer.wrap(getOptions);
        int tsVal = -1;
        int tsecr = -1;
        
        while(bb.hasRemaining()){
        	byte kind = bb.get();
        	
        	if(kind != 1){
            	byte length = bb.get();
            	
            	if(kind != 8){
            		for (int i = 0; i < length -2 ; i++) {
    					bb.get();
    				}
            	} else {
            		tsVal = bb.getInt();
            		tsecr = bb.getInt();
            	}
        	}
        }
		
		byte[] newOptions = new byte[20];
		
        ByteBuffer newbb = ByteBuffer.wrap(newOptions);
        
        //Maximum segment size: 1460 bytes
        newbb.put((byte) 0x02);
        newbb.put((byte) 0x04);
        newbb.put((byte) 0x05);
        newbb.put((byte) 0xb4);
        
        //TCP SACK permited: true
        newbb.put((byte) 0x04);
        newbb.put((byte) 0x02);
        
        //Timestamps: tsval:from get, tsecr 0
        newbb.put((byte) 0x08);
        newbb.put((byte) 0x0a);
        newbb.putInt(tsVal);
        newbb.putInt(0);
        
        //NOP
        newbb.put((byte) 0x01);
        
        //WindowScale: 7 (multiply by 128)
        newbb.put((byte) 0x03);
        newbb.put((byte) 0x03);
        newbb.put((byte) 0x07);
        
        return newOptions;
	}

	public byte[] getOptionsWithNewTsValues(int newTsValue,
			int newTSecr, byte[] options) {
        ByteBuffer bb = ByteBuffer.wrap(options);
        byte[] newOptions = new byte[options.length];
        ByteBuffer newbb = ByteBuffer.wrap(newOptions);
        
        while(bb.hasRemaining()){
        	byte kind = bb.get();
        	newbb.put(kind);
        	
        	if(kind != 1){
            	byte length = bb.get();
            	newbb.put(length);
            	
            	if(kind != 8){
            		for (int i = 0; i < length -2 ; i++) {
    					newbb.put(bb.get());
    				}
            	} else {
            		int tsVal = bb.getInt();
            		int tsecr = bb.getInt();
            		
            		newbb.putInt(newTsValue);
            		newbb.putInt(newTSecr);
            	}
        	}
        }
        
        return newOptions;
	}

}
