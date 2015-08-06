package br.ufpe.gprt.floodlight.transparentCache;

import java.nio.ByteBuffer;
import java.util.Random;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;

import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.OFPort;

import com.google.common.primitives.UnsignedInteger;

public class GTPPayloadContext {
	
	private byte[] ackOptions = new byte[] {
			(byte) 0x01, (byte) 0x01,
			(byte) 0x08, (byte) 0x0a, 
//			(byte) 0x00, (byte) 0x64, (byte) 0xf2, (byte) 0xae, 
//			(byte) 0x00, (byte) 0x5a, (byte) 0x2c, (byte) 0x6e
	};
	
	private byte[] httpDataOptions = new byte[] {
			(byte) 0x01, (byte) 0x01,
			(byte) 0x08, (byte) 0x0a, 
//			(byte) 0x00, (byte) 0x2e, (byte) 0xe7, (byte) 0x7a, 
//			(byte) 0x00, (byte) 0x27, (byte) 0x3a, (byte) 0xb9
	};

	private IPv4 ip;
	private TCP tcp;

	private GTPTunnelContext tunnelContext;

	private OFPort port;

	private IOFSwitch sw;

	private int tsecr;

	private int tsVal;

	public void updateContext(IPv4 gtpIp, OFPort port, IOFSwitch sw) {
		
		this.ip = gtpIp;
		this.port = port;
		this.sw = sw;
		short identification = this.ip.getIdentification();
		
		if(identification == 0){
			//                            A prime
			short s = (short) (new Random(7499)).nextInt(Short.MAX_VALUE + 1);
			this.ip.setIdentification(s);
		}

		if (gtpIp.getProtocol().equals(IpProtocol.TCP)) {

			this.tcp = (TCP) gtpIp.getPayload();
			
			if(this.tcp.getOptions() != null){
				this.getTimeStampFromOptions(this.tcp.getOptions());
			} else {
				this.tsecr = -1;
				this.tsVal = -1;
			}
		}
	}

	private void getTimeStampFromOptions(byte[] options) {
        ByteBuffer bb = ByteBuffer.wrap(options);
        
        while(bb.hasRemaining()){
        	byte kind = bb.get();
        	
        	if(kind != 1){
            	byte length = bb.get();
            	
            	if(kind != 8){
            		for (int i = 0; i < length -2 ; i++) {
    					bb.get();
    				}
            	} else {
            		this.tsVal = bb.getInt();
            		this.tsecr = bb.getInt();
            	}
        	}
        }
	}
	
	private byte[] getAckOptions(){
		byte[] options = new byte[12];
		
        ByteBuffer bb = ByteBuffer.wrap(options);
        
        for (int i = 0; i < ackOptions.length; i++) {
			bb.put(ackOptions[i]);
		}
        this.tsVal++;
        this.tsecr++;
        bb.putInt(this.tsVal);
        bb.putInt(this.tsecr);

        return options;
	}
	
	private byte[] getHttpDataOptions(){
		byte[] options = new byte[12];
		
        ByteBuffer bb = ByteBuffer.wrap(options);
        
        for (int i = 0; i < httpDataOptions.length; i++) {
			bb.put(httpDataOptions[i]);
		}
        this.tsVal++;
        this.tsecr++;
        bb.putInt(this.tsVal);
        bb.putInt(this.tsecr);

        return options;
	}

	public IPv4 getACK(int payloadSizeInBytes) {
		short flags = this.tcp.getFlags();
		int seqNumber = this.tcp.getSequence();
		int ackNumber = this.tcp.getAcknowledge();
		byte[] options = this.tcp.getOptions();
		short windowSize = this.tcp.getWindowSize();
		
		this.tcp.setFlags((short)0x010);
		this.tcp.setOptions(this.getAckOptions());
		this.tcp.setWindowSize((short)0xe3);
		this.ip.setIdentification((short)(this.ip.getIdentification()+1));
//		byte[] bytes = this.tcp.getPayload().serialize();
		System.out.println("Payload size is "+payloadSizeInBytes);
		System.out.println("Seq is "+this.tcp.getSequence());
		UnsignedInteger uAck = UnsignedInteger.asUnsigned(ackNumber);
		UnsignedInteger uSeqNum = UnsignedInteger.asUnsigned(seqNumber);

		System.out.println("Ack is "+this.tcp.getAcknowledge());
		System.out.println("uAck is "+uAck);
		this.tcp.setAcknowledge(uAck.add(UnsignedInteger.asUnsigned(payloadSizeInBytes)).intValue());
		this.tcp.setSequence(uSeqNum.add(UnsignedInteger.ONE).intValue());
		this.tcp.setPayload(null);

		IPv4 context = (IPv4)this.ip.clone();
		this.tcp.setFlags(flags);
//		this.tcp.setSequence(seqNumber);
//		this.tcp.setAcknowledge(ackNumber);
		this.tcp.setOptions(options);
		this.tcp.setWindowSize(windowSize);
		
		return context;
	}

	public void setTunnelContext(GTPTunnelContext contextPerIpperPort) {
		this.tunnelContext = contextPerIpperPort;
	}

	public IPv4 getTunneledPayloadOf(byte[] bytes){
		IPacket payload = this.tcp.getPayload();
		short flags = this.tcp.getFlags();
		byte[] options = this.tcp.getOptions();
		
		this.tcp.setPayload(new Data(bytes));
		this.tcp.setFlags((short)0x018);
		this.tcp.setOptions(this.getHttpDataOptions());
		this.tcp.setWindowSize((short)227);

		this.ip.setIdentification((short)(this.ip.getIdentification()+1));

		this.ip.serialize();
		IPv4 cloneGTPIp = (IPv4)this.ip.clone();

//		Ethernet tunnelClone = this.tunnelContext.getPacketWithPayload(this.gtpIp);

		this.tcp.setPayload(payload);
		this.tcp.setFlags(flags);
		this.tcp.setOptions(options);
		return  cloneGTPIp;
	}

	public GTPTunnelContext getTunnelContext() {
		return tunnelContext;
	}

	public IPv4 getTunneledPayloadOf(TCP tcp2) {
		TCP clonePayload = getPayloadOf(tcp2);
		this.ip.setPayload(clonePayload);
		clonePayload.setParent(this.ip);
		clonePayload.setWindowSize((short)0xe3);
		clonePayload.setOptions(this.getHttpDataOptions());


		this.ip.setIdentification((short)(this.ip.getIdentification()+1));
		
		clonePayload.resetChecksum();
		IPv4 cloneGTPIp = (IPv4)this.ip.clone();
		
		this.ip.setPayload(this.tcp);
		this.tcp.resetChecksum();
		return cloneGTPIp;
	}

	public TCP getPayloadOf(TCP tcp2) {
		TCP clonePayload = (TCP)tcp2.clone();
		clonePayload.setAcknowledge(this.tcp.getAcknowledge());
//		clonePayload.setAcknowledge(92);
		clonePayload.setSequence(this.tcp.getSequence());
		clonePayload.setSourcePort(this.tcp.getSourcePort());
		clonePayload.setDestinationPort(this.tcp.getDestinationPort());
		return clonePayload;
	}
	
	

	public OFPort getOFPort() {
		return port;
	}

	public IOFSwitch getSw() {
		return sw;
	}

	public int getTsecr() {
		return tsecr;
	}

	public int getTsVal() {
		return tsVal;
	}

	public IPv4 getACK(int payloadSizeInBytes, int tsVal2, int tsecr2) {
		short flags = this.tcp.getFlags();
		int seqNumber = this.tcp.getSequence();
		int ackNumber = this.tcp.getAcknowledge();
		byte[] options = this.tcp.getOptions();
		short windowSize = this.tcp.getWindowSize();
		
		this.tcp.setFlags((short)0x010);
		this.tcp.setOptions(this.getAckOptions(tsVal2, tsecr2));
		this.tcp.setWindowSize((short)0xe3);
		this.ip.setIdentification((short)(this.ip.getIdentification()+1));
//		byte[] bytes = this.tcp.getPayload().serialize();
		System.out.println("Payload size is "+payloadSizeInBytes);
		System.out.println("Seq is "+this.tcp.getSequence());
		UnsignedInteger uAck = UnsignedInteger.asUnsigned(ackNumber);
		UnsignedInteger uSeqNum = UnsignedInteger.asUnsigned(seqNumber);

		System.out.println("Ack is "+this.tcp.getAcknowledge());
		System.out.println("uAck is "+uAck);
		this.tcp.setAcknowledge(uAck.add(UnsignedInteger.asUnsigned(payloadSizeInBytes)).intValue());
		this.tcp.setSequence(uSeqNum.add(UnsignedInteger.ONE).intValue());
		this.tcp.setPayload(null);

		this.tcp.resetChecksum();
		this.ip.resetChecksum();
		
		IPv4 context = (IPv4)this.ip.clone();
		
		this.tcp.setFlags(flags);
//		this.tcp.setSequence(seqNumber);
//		this.tcp.setAcknowledge(ackNumber);
		this.tcp.setOptions(options);
		this.tcp.setWindowSize(windowSize);
		
		this.tcp.resetChecksum();
		this.ip.resetChecksum();
		
		return context;

	}

	private byte[] getAckOptions(int tsVal2, int tsecr2) {
		byte[] options = new byte[12];
		
        ByteBuffer bb = ByteBuffer.wrap(options);
        
        for (int i = 0; i < ackOptions.length; i++) {
			bb.put(ackOptions[i]);
		}
        this.tsVal = tsecr2 + 1;
        this.tsecr = tsVal2;
        bb.putInt(this.tsVal);
        bb.putInt(this.tsecr);

        return options;
	}
	
}
